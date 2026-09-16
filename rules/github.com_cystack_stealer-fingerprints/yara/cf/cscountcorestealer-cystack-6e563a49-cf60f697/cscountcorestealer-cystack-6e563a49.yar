rule CSCountCoreStealer_cystack_6e563a49
{
    meta:
        family = "CSCountCoreStealer"
        fingerprint_id = "cystack_6e563a49"

    strings:
        $key_0 = "Arch:" ascii
        $key_1 = "Count Core:" ascii
        $key_2 = "File Location:" ascii
        $key_3 = "Hostname:" ascii
        $key_4 = "IP Address:" ascii
        $key_5 = "User Info:" ascii
        $key_6 = "Version:" ascii

    condition:
        all of ($key_*)
}