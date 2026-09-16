rule Cthulhu_Stealer_cystack_eeff932e
{
    meta:
        family = "Cthulhu Stealer"
        fingerprint_id = "cystack_eeff932e"

    strings:
        $key_0 = "BuildID:" ascii
        $key_1 = "City:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Debanks:" ascii
        $key_4 = "Graphics/Displays:" ascii
        $key_5 = "Hardware:" ascii
        $key_6 = "Hardware Overview:" ascii
        $key_7 = "IP:" ascii
        $key_8 = "Intel HD Graphics 5000:" ascii
        $key_9 = "MetaMask Info:" ascii
        $key_10 = "PHL 243V5:" ascii
        $key_11 = "Software:" ascii
        $key_12 = "System Software Overview:" ascii
        $key_13 = "Userinfo:" ascii

    condition:
        all of ($key_*)
}