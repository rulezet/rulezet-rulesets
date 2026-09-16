rule Hangover_Smackdown_Downloader {
    strings:
        $a1 = "DownloadComplete"
        $a2 = "DownloadProgress"
        $a3 = "DownloadError"
        $a4 = "UserControl"
        $a5 = "MSVBVM60.DLL"

        $b1 = "syslide"
        $b2 = "frmMina"
        $b3 = "Soundsman"
        $b4 = "New_upl"
        $b5 = "MCircle"
        $b6 = "shells_DataArrival"
        
    condition:
        3 of ($a*) and 1 of ($b*)

}