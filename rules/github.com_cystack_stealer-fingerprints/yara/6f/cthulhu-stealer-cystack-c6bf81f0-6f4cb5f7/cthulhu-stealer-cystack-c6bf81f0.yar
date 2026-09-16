rule Cthulhu_Stealer_cystack_c6bf81f0
{
    meta:
        family = "Cthulhu Stealer"
        fingerprint_id = "cystack_c6bf81f0"

    strings:
        $key_0 = "Apple M1 Pro:" ascii
        $key_1 = "BuildID:" ascii
        $key_2 = "City:" ascii
        $key_3 = "Color LCD:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Debanks:" ascii
        $key_6 = "G274F:" ascii
        $key_7 = "Graphics/Displays:" ascii
        $key_8 = "Hardware:" ascii
        $key_9 = "Hardware Overview:" ascii
        $key_10 = "IP:" ascii
        $key_11 = "MetaMask Info:" ascii
        $key_12 = "Software:" ascii
        $key_13 = "System Software Overview:" ascii
        $key_14 = "Userinfo:" ascii

    condition:
        all of ($key_*)
}