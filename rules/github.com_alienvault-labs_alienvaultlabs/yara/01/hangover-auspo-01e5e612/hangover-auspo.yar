rule Hangover_Auspo {
    strings:
        $a1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV2)"
        $a2 = "POWERS"
        $a3 = "AUSTIN"
        
    condition:
        all of them

}