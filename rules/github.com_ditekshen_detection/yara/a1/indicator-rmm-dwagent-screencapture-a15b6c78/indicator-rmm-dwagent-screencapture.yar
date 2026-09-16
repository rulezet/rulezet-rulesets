rule INDICATOR_RMM_DWAgent_ScreenCapture {
    meta:
        author = "ditekSHen"
        description = "Detect DWAgent Remote Administration Tool Screen Capture Module"
        clamav1 = "INDICATOR.Win.RMM.DWAgent-ScreenCapture"
        reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
        reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
        reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
        reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
    strings:
        $s1 = "DWAgentLib" fullword wide
        $s2 = "PYTHONHOME" wide
        $s3 = "VirtualBox" wide
        $s4 = "VMware" wide
        $s5 = "ScreenCapture::prepareCursor#" ascii
        $s6 = "ScreenCapture::getMonitorCount#" ascii
        $s7 = "ScreenCapture::token" ascii
        $s8 = "dwascreencapture" ascii
        $s9 = "inputKeyboard CTRLALTCANC" ascii
        $s10 = "_Z34ScreenCaptureNativeMonitorEnumProc" ascii
        $s11 = "_Z41ScreenCaptureNativeCreateWindowThreadProc" ascii
        $s12 = "_ZN13ScreenCapture" ascii
        $s13 = "isUserInAdminGroup" ascii
    condition:
        uint16(0) == 0x5a4d and 7 of them
}