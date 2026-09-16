rule Aetheris_Stealer_cystack_8a71bd70
{
    meta:
        family = "Aetheris Stealer"
        fingerprint_id = "cystack_8a71bd70"

    strings:
        $key_0 = "CLR Version:" ascii
        $key_1 = "CPU Name:" ascii
        $key_2 = "Default Gateway:" ascii
        $key_3 = "External IP:" ascii
        $key_4 = "Hwid:" ascii
        $key_5 = "Input ISO:" ascii
        $key_6 = "Internal IP:" ascii
        $key_7 = "Logical Cores:" ascii
        $key_8 = "Machine:" ascii
        $key_9 = "Now:" ascii
        $key_10 = "OS Arch:" ascii
        $key_11 = "OS Build:" ascii
        $key_12 = "OS Product:" ascii
        $key_13 = "RAM Available (MB):" ascii
        $key_14 = "RAM Total (MB):" ascii
        $key_15 = "User:" ascii
        $key_16 = "User Domain:" ascii

    condition:
        all of ($key_*)
}