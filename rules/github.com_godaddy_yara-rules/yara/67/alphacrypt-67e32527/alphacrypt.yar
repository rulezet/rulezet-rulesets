rule alphacrypt {
    meta:
        info = "AlphaCrypt Ransomware"

    strings:
                                $config_data = { 54 68 69 73 20 70 72 6F 67 72 FE ?? ?? FE 61 6E 
            6E 6F 74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20 6D 6F 64 65 }                          

    condition:
        $config_data
}