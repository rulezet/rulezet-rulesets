rule AMOS_Stealer_cystack_198df320
{
    meta:
        family = "AMOS Stealer"
        fingerprint_id = "cystack_198df320"

    strings:
        $key_0 = "Apple M3 Pro:" ascii
        $key_1 = "BenQ PD3205U:" ascii
        $key_2 = "City:" ascii
        $key_3 = "Color LCD:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Debanks:" ascii
        $key_6 = "Graphics/Displays:" ascii
        $key_7 = "Hardware:" ascii
        $key_8 = "Hardware Overview:" ascii
        $key_9 = "IP:" ascii
        $key_10 = "MSI MD241P:" ascii
        $key_11 = "MetaMask Info:" ascii
        $key_12 = "Software:" ascii
        $key_13 = "System Software Overview:" ascii
        $key_14 = "Userinfo:" ascii

    condition:
        all of ($key_*)
}