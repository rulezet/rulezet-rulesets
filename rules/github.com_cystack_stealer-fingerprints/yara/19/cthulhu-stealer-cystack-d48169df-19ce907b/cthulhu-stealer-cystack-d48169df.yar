rule Cthulhu_Stealer_cystack_d48169df
{
    meta:
        family = "Cthulhu Stealer"
        fingerprint_id = "cystack_d48169df"

    strings:
        $key_0 = "BuildID:" ascii
        $key_1 = "City:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Hardware:" ascii
        $key_4 = "IP:" ascii
        $key_5 = "MetaMask Info:" ascii
        $key_6 = "Software:" ascii
        $key_7 = "Userinfo:" ascii

    condition:
        all of ($key_*)
}