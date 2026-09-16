rule Cthulhu_Stealer_cystack_9fb6f3f1
{
    meta:
        family = "Cthulhu Stealer"
        fingerprint_id = "cystack_9fb6f3f1"

    strings:
        $key_0 = "BuildID:" ascii
        $key_1 = "City:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Debanks:" ascii
        $key_4 = "Graphics/Displays:" ascii
        $key_5 = "Hardware:" ascii
        $key_6 = "Hardware Overview:" ascii
        $key_7 = "IP:" ascii
        $key_8 = "MetaMask Info:" ascii
        $key_9 = "Radeon Pro 570:" ascii
        $key_10 = "Software:" ascii
        $key_11 = "System Software Overview:" ascii
        $key_12 = "Userinfo:" ascii

    condition:
        all of ($key_*)
}