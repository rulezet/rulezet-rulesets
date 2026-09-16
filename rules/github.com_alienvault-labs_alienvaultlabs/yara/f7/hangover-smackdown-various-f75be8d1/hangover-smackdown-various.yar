rule Hangover_Smackdown_various {
    strings:
        $a1 = "pranVacrhan"
        $a2 = "NaramGaram"
        $a3 = "vampro"
        $a4 = "AngelPro"
        
        $b1 = "VBA6.DLL"
        $b2 = "advpack"
        $b3 = "IsNTAdmin"
        
        
    condition:
        1 of ($a*) and all of ($b*)

}