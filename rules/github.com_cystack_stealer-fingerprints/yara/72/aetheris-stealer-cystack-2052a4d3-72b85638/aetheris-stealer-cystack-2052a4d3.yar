rule Aetheris_Stealer_cystack_2052a4d3
{
    meta:
        family = "Aetheris Stealer"
        fingerprint_id = "cystack_2052a4d3"

    strings:
        $key_0 = "CLR Version:" ascii
        $key_1 = "CPU Name:" ascii
        $key_2 = "Clipboard:" ascii
        $key_3 = "Default Gateway:" ascii
        $key_4 = "External IP:" ascii
        $key_5 = "Hwid:" ascii
        $key_6 = "Input ISO:" ascii
        $key_7 = "Internal IP:" ascii
        $key_8 = "Logical Cores:" ascii
        $key_9 = "Machine:" ascii
        $key_10 = "Now:" ascii
        $key_11 = "OS Arch:" ascii
        $key_12 = "OS Build:" ascii
        $key_13 = "OS Product:" ascii
        $key_14 = "RAM Available (MB):" ascii
        $key_15 = "RAM Total (MB):" ascii
        $key_16 = "User:" ascii
        $key_17 = "User Domain:" ascii

    condition:
        all of ($key_*)
}