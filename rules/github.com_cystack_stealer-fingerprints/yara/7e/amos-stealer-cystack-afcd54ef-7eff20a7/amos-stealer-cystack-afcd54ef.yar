rule AMOS_Stealer_cystack_afcd54ef
{
    meta:
        family = "AMOS Stealer"
        fingerprint_id = "cystack_afcd54ef"

    strings:
        $key_0 = "City:" ascii
        $key_1 = "Country:" ascii
        $key_2 = "Debanks:" ascii
        $key_3 = "Graphics/Displays:" ascii
        $key_4 = "Hardware:" ascii
        $key_5 = "Hardware Overview:" ascii
        $key_6 = "IP:" ascii
        $key_7 = "Intel Iris Plus Graphics 640:" ascii
        $key_8 = "MetaMask Info:" ascii
        $key_9 = "Software:" ascii
        $key_10 = "System Software Overview:" ascii
        $key_11 = "Userinfo:" ascii

    condition:
        all of ($key_*)
}