rule Aetheris_Stealer_cystack_9a0496c3
{
    meta:
        family = "Aetheris Stealer"
        fingerprint_id = "cystack_9a0496c3"

    strings:
        $key_0 = "CPU Name:" ascii
        $key_1 = "Clipboard:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Default Gateway:" ascii
        $key_4 = "External IP:" ascii
        $key_5 = "FileLocation:" ascii
        $key_6 = "Hwid:" ascii
        $key_7 = "Input ISO:" ascii
        $key_8 = "Internal IP:" ascii
        $key_9 = "Keyboard:" ascii
        $key_10 = "Logical Cores:" ascii
        $key_11 = "Machine:" ascii
        $key_12 = "Now:" ascii
        $key_13 = "OS Arch:" ascii
        $key_14 = "OS Build:" ascii
        $key_15 = "OS Product:" ascii
        $key_16 = "RAM Available (MB):" ascii
        $key_17 = "RAM Total (MB):" ascii
        $key_18 = "Screensize:" ascii
        $key_19 = "System Language:" ascii
        $key_20 = "User:" ascii
        $key_21 = "User Domain:" ascii

    condition:
        all of ($key_*)
}