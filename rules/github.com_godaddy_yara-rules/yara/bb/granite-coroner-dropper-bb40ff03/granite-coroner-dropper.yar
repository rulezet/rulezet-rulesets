rule granite_coroner_dropper {
    meta:
        description = "Payload dropper for password theft or keylogging"

    strings:
        $mz = "MZ"

                $granitea = "GRANITE" nocase
        $granitew = "GRANITE" nocase wide
        $jocastaeluviuma = "JOCASTAELUVIUM" nocase
        $jocastaeluviumw = "JOCASTAELUVIUM" nocase wide

                $coronera = "CORONER" nocase
        $coronerw = "CORONER" nocase wide
        $bolshiecharitya = "BOLSHIECHARITY" nocase
        $bolshiecharityw = "BOLSHIECHARITY" nocase wide

                $cypher_cryptor = "Cypher Cryptor" wide

    condition:
        $mz at 0 and 
            ($granitea and $jocastaeluviuma) or
            ($granitew and $jocastaeluviumw) or
            ($coronera and $bolshiecharitya) or
            ($coronerw and $bolshiecharityw) or
        $cypher_cryptor
}