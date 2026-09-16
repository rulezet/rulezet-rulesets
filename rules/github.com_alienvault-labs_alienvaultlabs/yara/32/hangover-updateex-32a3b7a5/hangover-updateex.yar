rule Hangover_UpdateEx {
    strings:
        $a1 = "UpdateEx"
        $a2 = "VBA6.DLL"
        $a3 = "MainEx"
        $a4 = "GetLogs"
        $a5 = "ProMan"
        $a6 = "RedMod"
        
    condition:
        all of them

}