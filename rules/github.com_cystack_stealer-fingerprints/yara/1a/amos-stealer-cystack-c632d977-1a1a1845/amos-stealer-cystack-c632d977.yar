rule AMOS_Stealer_cystack_c632d977
{
    meta:
        family = "AMOS Stealer"
        fingerprint_id = "cystack_c632d977"

    strings:
        $key_0 = "Apple M3:" ascii
        $key_1 = "City:" ascii
        $key_2 = "Color LCD:" ascii
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