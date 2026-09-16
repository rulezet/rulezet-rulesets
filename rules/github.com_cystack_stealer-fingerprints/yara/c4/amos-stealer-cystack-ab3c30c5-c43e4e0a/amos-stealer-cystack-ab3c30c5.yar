rule AMOS_Stealer_cystack_ab3c30c5
{
    meta:
        family = "AMOS Stealer"
        fingerprint_id = "cystack_ab3c30c5"

    strings:
        $key_0 = "City:" ascii
        $key_1 = "Country:" ascii
        $key_2 = "Debanks:" ascii
        $key_3 = "Graphics/Displays:" ascii
        $key_4 = "IP:" ascii
        $key_5 = "MetaMask Info:" ascii
        $key_6 = "Software:" ascii
        $key_7 = "Userinfo:" ascii

    condition:
        all of ($key_*)
}