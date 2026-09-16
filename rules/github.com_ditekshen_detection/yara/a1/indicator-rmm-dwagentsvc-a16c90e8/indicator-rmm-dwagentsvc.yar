rule INDICATOR_RMM_DWAgentSVC {
    meta:
        author = "ditekSHen"
        description = "Detect DWAgent Remote Administration Tool service"
        clamav1 = "INDICATOR.Win.RMM.DWAgent-SVC"
        reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
        reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
        reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
        reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
    strings:
        $s1 = "\\native\\dwagupd.dll" wide
        $s2 = "\\native\\dwagsvc.exe\" run" wide
        $s3 = "CreateServiceW" fullword ascii
        $s4 = /dwagent\.(pid|start|stop)/ wide
        $s5 = "Check updating..." wide
    condition:
        uint16(0) == 0x5a4d and 4 of them
}