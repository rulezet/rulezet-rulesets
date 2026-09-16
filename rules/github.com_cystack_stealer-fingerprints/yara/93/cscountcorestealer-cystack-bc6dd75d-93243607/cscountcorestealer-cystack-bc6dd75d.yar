rule CSCountCoreStealer_cystack_bc6dd75d
{
    meta:
        family = "CSCountCoreStealer"
        fingerprint_id = "cystack_bc6dd75d"

    strings:
        $key_0 = "Arch:" ascii
        $key_1 = "Count Core:" ascii
        $key_2 = "Cpu:" ascii
        $key_3 = "File Location:" ascii
        $key_4 = "Gpu:" ascii
        $key_5 = "Hostname:" ascii
        $key_6 = "IP Address:" ascii
        $key_7 = "Mac:" ascii
        $key_8 = "Release:" ascii
        $key_9 = "Type:" ascii
        $key_10 = "User Info:" ascii
        $key_11 = "Uuid:" ascii

    condition:
        all of ($key_*)
}