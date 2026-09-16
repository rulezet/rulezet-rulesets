rule Cthulhu_Stealer_cystack_d883046a
{
    meta:
        family = "Cthulhu Stealer"
        fingerprint_id = "cystack_d883046a"

    strings:
        $key_0 = "Apple M1 Pro:" ascii
        $key_1 = "BuildID:" ascii
        $key_2 = "City:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Debanks:" ascii
        $key_5 = "Graphics/Displays:" ascii
        $key_6 = "Hardware:" ascii
        $key_7 = "Hardware Overview:" ascii
        $key_8 = "IP:" ascii
        $key_9 = "MetaMask Info:" ascii
        $key_10 = "Software:" ascii
        $key_11 = "System Software Overview:" ascii
        $key_12 = "Userinfo:" ascii

    condition:
        all of ($key_*)
}