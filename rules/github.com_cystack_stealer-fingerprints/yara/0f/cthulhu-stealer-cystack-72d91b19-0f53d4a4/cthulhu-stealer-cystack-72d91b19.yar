rule Cthulhu_Stealer_cystack_72d91b19
{
    meta:
        family = "Cthulhu Stealer"
        fingerprint_id = "cystack_72d91b19"

    strings:
        $key_0 = "BuildID:" ascii
        $key_1 = "City:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Graphics/Displays:" ascii
        $key_4 = "Hardware:" ascii
        $key_5 = "IP:" ascii
        $key_6 = "MetaMask Info:" ascii
        $key_7 = "Software:" ascii
        $key_8 = "Userinfo:" ascii

    condition:
        all of ($key_*)
}