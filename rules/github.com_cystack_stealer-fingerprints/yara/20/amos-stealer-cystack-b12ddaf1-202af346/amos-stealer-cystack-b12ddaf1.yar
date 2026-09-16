rule AMOS_Stealer_cystack_b12ddaf1
{
    meta:
        family = "AMOS Stealer"
        fingerprint_id = "cystack_b12ddaf1"

    strings:
        $key_0 = "City:" ascii
        $key_1 = "Country:" ascii
        $key_2 = "Debanks:" ascii
        $key_3 = "Graphics/Displays:" ascii
        $key_4 = "Hardware:" ascii
        $key_5 = "Hardware Overview:" ascii
        $key_6 = "IP:" ascii
        $key_7 = "Intel UHD Graphics 630:" ascii
        $key_8 = "MetaMask Info:" ascii
        $key_9 = "PHL 247E6:" ascii
        $key_10 = "Software:" ascii
        $key_11 = "System Software Overview:" ascii
        $key_12 = "Userinfo:" ascii

    condition:
        all of ($key_*)
}