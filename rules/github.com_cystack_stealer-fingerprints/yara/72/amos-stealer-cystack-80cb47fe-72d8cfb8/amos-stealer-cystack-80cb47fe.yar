rule AMOS_Stealer_cystack_80cb47fe
{
    meta:
        family = "AMOS Stealer"
        fingerprint_id = "cystack_80cb47fe"

    strings:
        $key_0 = "AMD FirePro D700:" ascii
        $key_1 = "BenQ EW3270U:" ascii
        $key_2 = "Cinema HD Display:" ascii
        $key_3 = "City:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Debanks:" ascii
        $key_6 = "Graphics/Displays:" ascii
        $key_7 = "Hardware:" ascii
        $key_8 = "Hardware Overview:" ascii
        $key_9 = "IP:" ascii
        $key_10 = "MetaMask Info:" ascii
        $key_11 = "Software:" ascii
        $key_12 = "System Software Overview:" ascii
        $key_13 = "Userinfo:" ascii

    condition:
        all of ($key_*)
}