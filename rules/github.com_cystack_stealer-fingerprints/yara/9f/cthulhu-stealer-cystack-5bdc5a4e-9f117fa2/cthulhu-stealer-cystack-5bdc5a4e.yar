rule Cthulhu_Stealer_cystack_5bdc5a4e
{
    meta:
        family = "Cthulhu Stealer"
        fingerprint_id = "cystack_5bdc5a4e"

    strings:
        $key_0 = "AMD Radeon Pro 5300M:" ascii
        $key_1 = "BuildID:" ascii
        $key_2 = "City:" ascii
        $key_3 = "Color LCD:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Debanks:" ascii
        $key_6 = "Graphics/Displays:" ascii
        $key_7 = "Hardware:" ascii
        $key_8 = "Hardware Overview:" ascii
        $key_9 = "IP:" ascii
        $key_10 = "Intel UHD Graphics 630:" ascii
        $key_11 = "MetaMask Info:" ascii
        $key_12 = "Software:" ascii
        $key_13 = "System Software Overview:" ascii
        $key_14 = "Userinfo:" ascii

    condition:
        all of ($key_*)
}