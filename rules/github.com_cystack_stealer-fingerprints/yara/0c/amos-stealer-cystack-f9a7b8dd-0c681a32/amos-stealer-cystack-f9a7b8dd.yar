rule AMOS_Stealer_cystack_f9a7b8dd
{
    meta:
        family = "AMOS Stealer"
        fingerprint_id = "cystack_f9a7b8dd"

    strings:
        $key_0 = "Apple M4 Pro:" ascii
        $key_1 = "City:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Debanks:" ascii
        $key_4 = "Graphics/Displays:" ascii
        $key_5 = "Hardware:" ascii
        $key_6 = "Hardware Overview:" ascii
        $key_7 = "IP:" ascii
        $key_8 = "MetaMask Info:" ascii
        $key_9 = "Software:" ascii
        $key_10 = "Studio Display:" ascii
        $key_11 = "System Software Overview:" ascii
        $key_12 = "Userinfo:" ascii

    condition:
        all of ($key_*)
}