rule Cthulhu_Stealer_cystack_8ae5163b
{
    meta:
        family = "Cthulhu Stealer"
        fingerprint_id = "cystack_8ae5163b"

    strings:
        $key_0 = "ATI Radeon HD 5870:" ascii
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
        $key_12 = "TOSHIBA-TV:" ascii
        $key_13 = "Userinfo:" ascii

    condition:
        all of ($key_*)
}