rule AMOS_Stealer_cystack_fbebf84e
{
    meta:
        family = "AMOS Stealer"
        fingerprint_id = "cystack_fbebf84e"

    strings:
        $key_0 = "City:" ascii
        $key_1 = "Color LCD:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Debanks:" ascii
        $key_4 = "Graphics/Displays:" ascii
        $key_5 = "Hardware:" ascii
        $key_6 = "Hardware Overview:" ascii
        $key_7 = "IP:" ascii
        $key_8 = "Intel Iris Pro:" ascii
        $key_9 = "MetaMask Info:" ascii
        $key_10 = "NVIDIA GeForce GT 750M:" ascii
        $key_11 = "Software:" ascii
        $key_12 = "System Software Overview:" ascii
        $key_13 = "Userinfo:" ascii

    condition:
        all of ($key_*)
}