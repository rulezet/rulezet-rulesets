rule Aetheris_Stealer_cystack_51d2539b
{
    meta:
        family = "Aetheris Stealer"
        fingerprint_id = "cystack_51d2539b"

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
        $key_11 = "Look for:" ascii
        $key_12 = "Machine:" ascii
        $key_13 = "Now:" ascii
        $key_14 = "OS Arch:" ascii
        $key_15 = "OS Build:" ascii
        $key_16 = "OS Product:" ascii
        $key_17 = "RAM Available (MB):" ascii
        $key_18 = "RAM Total (MB):" ascii
        $key_19 = "Screensize:" ascii
        $key_20 = "System Language:" ascii
        $key_21 = "User:" ascii
        $key_22 = "User Domain:" ascii

    condition:
        all of ($key_*)
}