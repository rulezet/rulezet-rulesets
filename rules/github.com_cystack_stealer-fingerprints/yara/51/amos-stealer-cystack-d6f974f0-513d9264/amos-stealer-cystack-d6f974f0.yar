rule AMOS_Stealer_cystack_d6f974f0
{
    meta:
        family = "AMOS Stealer"
        fingerprint_id = "cystack_d6f974f0"

    strings:
        $key_0 = "Apple M2:" ascii
        $key_1 = "BenQ GW2480:" ascii
        $key_2 = "City:" ascii
        $key_3 = "Color LCD:" ascii
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