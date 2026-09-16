rule Aetheris_Stealer_cystack_6a42be28
{
    meta:
        family = "Aetheris Stealer"
        fingerprint_id = "cystack_6a42be28"

    strings:
        $key_0 = "Buildtag:" ascii
        $key_1 = "CPU Name:" ascii
        $key_2 = "Clipboard:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Default Gateway:" ascii
        $key_5 = "External IP:" ascii
        $key_6 = "FileLocation:" ascii
        $key_7 = "Hwid:" ascii
        $key_8 = "Input ISO:" ascii
        $key_9 = "Internal IP:" ascii
        $key_10 = "Keyboard:" ascii
        $key_11 = "Logical Cores:" ascii
        $key_12 = "Look for:" ascii
        $key_13 = "Machine:" ascii
        $key_14 = "Now:" ascii
        $key_15 = "OS Arch:" ascii
        $key_16 = "OS Build:" ascii
        $key_17 = "OS Product:" ascii
        $key_18 = "RAM Available (MB):" ascii
        $key_19 = "RAM Total (MB):" ascii
        $key_20 = "Screensize:" ascii
        $key_21 = "System Language:" ascii
        $key_22 = "User:" ascii
        $key_23 = "User Domain:" ascii

    condition:
        all of ($key_*)
}