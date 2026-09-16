rule INDICATOR_OSX_RMM_DWAgent {
    meta:
        author = "ditekSHen"
        description = "Detect DWAgent Remote Administration Tool macOS run"
        clamav1 = "INDICATOR.Osx.RMM.DWAgent-RUN"
        reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
        reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
        reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
        reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
    strings:
        $s1 = "net.dwservice.DWAgent" ascii
        $s2 = "-[DWADelegate" ascii
        $s3 = "customWindowsToEnterFullScreenForWindow:onScreen:" ascii
    condition:
        uint16(0) == 0xfeca and all of them
}