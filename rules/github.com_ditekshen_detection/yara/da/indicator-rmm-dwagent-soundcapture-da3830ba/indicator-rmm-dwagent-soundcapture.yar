rule INDICATOR_RMM_DWAgent_SoundCapture {
    meta:
        author = "ditekSHen"
        description = "Detect DWAgent Remote Administration Tool Sound Capture Module"
        clamav1 = "INDICATOR.Win.RMM.DWAgent-SoundCapture"
        reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
        reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
        reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
        reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
    strings:
        $s1 = "DWASoundCapture" ascii
        $s2 = /_Z\d{2}DWASoundCapture/ ascii
        $s3 = "_Z6recordPvS_" ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}