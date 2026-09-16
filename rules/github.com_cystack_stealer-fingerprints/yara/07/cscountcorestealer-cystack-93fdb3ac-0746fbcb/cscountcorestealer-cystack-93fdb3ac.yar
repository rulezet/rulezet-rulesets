rule CSCountCoreStealer_cystack_93fdb3ac
{
    meta:
        family = "CSCountCoreStealer"
        fingerprint_id = "cystack_93fdb3ac"

    strings:
        $key_0 = "Arch:" ascii
        $key_1 = "Count Core:" ascii
        $key_2 = "File Location:" ascii
        $key_3 = "Hostname:" ascii
        $key_4 = "IP Address:" ascii
        $key_5 = "Release:" ascii
        $key_6 = "Type:" ascii
        $key_7 = "User Info:" ascii
        $key_8 = "Version:" ascii

    condition:
        all of ($key_*)
}