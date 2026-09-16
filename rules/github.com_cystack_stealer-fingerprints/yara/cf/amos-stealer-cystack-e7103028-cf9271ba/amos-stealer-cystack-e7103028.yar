rule AMOS_Stealer_cystack_e7103028
{
    meta:
        family = "AMOS Stealer"
        fingerprint_id = "cystack_e7103028"

    strings:
        $key_0 = "Board-ID:" ascii
        $key_1 = "City:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Debanks:" ascii
        $key_4 = "Graphics/Displays:" ascii
        $key_5 = "Hardware:" ascii
        $key_6 = "IP:" ascii
        $key_7 = "MetaMask Info:" ascii
        $key_8 = "Software:" ascii
        $key_9 = "Userinfo:" ascii

    condition:
        all of ($key_*)
}