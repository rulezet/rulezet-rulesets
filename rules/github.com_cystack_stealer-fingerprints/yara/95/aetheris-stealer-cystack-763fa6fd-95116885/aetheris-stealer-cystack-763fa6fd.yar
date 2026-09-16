rule Aetheris_Stealer_cystack_763fa6fd
{
    meta:
        family = "Aetheris Stealer"
        fingerprint_id = "cystack_763fa6fd"

    strings:
        $key_0 = "CPU Name:" ascii
        $key_1 = "Clipboard:" ascii
        $key_2 = "Default Gateway:" ascii
        $key_3 = "External IP:" ascii
        $key_4 = "Input ISO:" ascii
        $key_5 = "Internal IP:" ascii
        $key_6 = "Logical Cores:" ascii
        $key_7 = "Machine:" ascii
        $key_8 = "Now:" ascii
        $key_9 = "OS Arch:" ascii
        $key_10 = "OS Build:" ascii
        $key_11 = "OS Product:" ascii
        $key_12 = "RAM Available (MB):" ascii
        $key_13 = "RAM Total (MB):" ascii
        $key_14 = "User:" ascii
        $key_15 = "User Domain:" ascii

    condition:
        all of ($key_*)
}