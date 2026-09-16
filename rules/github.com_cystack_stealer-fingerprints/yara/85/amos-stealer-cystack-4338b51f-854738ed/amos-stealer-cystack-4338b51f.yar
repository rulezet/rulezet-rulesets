rule AMOS_Stealer_cystack_4338b51f
{
    meta:
        family = "AMOS Stealer"
        fingerprint_id = "cystack_4338b51f"

    strings:
        $key_0 = "Apple M2 Pro:" ascii
        $key_1 = "City:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Debanks:" ascii
        $key_4 = "Graphics/Displays:" ascii
        $key_5 = "Hardware:" ascii
        $key_6 = "Hardware Overview:" ascii
        $key_7 = "IP:" ascii
        $key_8 = "MetaMask Info:" ascii
        $key_9 = "Software:" ascii
        $key_10 = "System Software Overview:" ascii
        $key_11 = "T27C350:" ascii
        $key_12 = "Userinfo:" ascii

    condition:
        all of ($key_*)
}