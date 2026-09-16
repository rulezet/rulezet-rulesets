rule INDICATOR_RMM_ConnectWise_ScreenConnect {
    meta:
        author = "ditekSHen"
        description = "Detects ConnectWise Control (formerly ScreenConnect). Review RMM Inventory"
        clamav1 = "INDICATOR.Win.RMM.ConnectWise-ScreenConnect"
        reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
        reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
        reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
        reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
    strings:
        $s1 = "FILESYSCREENCONNECT.CORE, VERSION=" wide
        $s2 = "feedback.screenconnect.com/Feedback.axd" wide
        $s3 = /ScreenConnect (Software|Client)/ wide
        $s4 = "ScreenConnect.InstallerActions!ScreenConnect." wide
        $s5 = "\\\\.\\Pipe\\TerminalServer\\SystemExecSrvr\\" wide
        $s6 = "\\jmorgan\\Source\\cwcontrol\\Custom\\DotNetRunner\\" wide
        $s7 = "ScreenConnect." ascii
        $s8 = "\\ScreenConnect.Core.pdb" ascii
        $s9 = "relay.screenconnect.com" ascii
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0xcfd0) and 3 of them
}