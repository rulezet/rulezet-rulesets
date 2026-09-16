rule Aetheris_Stealer_cystack_7d0668ba
{
    meta:
        family = "Aetheris Stealer"
        fingerprint_id = "cystack_7d0668ba"

    strings:
        $key_0 = "CPU Name:" ascii
        $key_1 = "Clipboard:" ascii
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
        $key_15 = "Screen Resolution:" ascii
        $key_16 = "Step 2:" ascii
        $key_17 = "Step 3:" ascii
        $key_18 = "Step 4:" ascii
        $key_19 = "Step 5:" ascii
        $key_20 = "User:" ascii
        $key_21 = "User Domain:" ascii

    condition:
        all of ($key_*)
}