rule Hangover_Deksila {
    strings:
        $a1 = "WinInetGet/0.1"
        $a2 = "dekstop2007.ico"
        $a3 = "mozila20"
        
    condition:
        all of them

}