rule Cthulhu_Stealer_cystack_000c0121
{
    meta:
        family = "Cthulhu Stealer"
        fingerprint_id = "cystack_000c0121"

    strings:
        $key_0 = "AMD Radeon RX 5500 XT:" ascii
        $key_1 = "BenQ GW2270:" ascii
        $key_2 = "BuildID:" ascii
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