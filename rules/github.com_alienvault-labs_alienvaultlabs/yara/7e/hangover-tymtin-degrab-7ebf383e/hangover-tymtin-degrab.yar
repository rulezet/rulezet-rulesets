rule Hangover_Tymtin_Degrab {
    strings:
        $a1 = "&dis=no&utp=op&mfol="
        $a2 = "value1=1&value2=2"
        
    condition:
        all of them

}