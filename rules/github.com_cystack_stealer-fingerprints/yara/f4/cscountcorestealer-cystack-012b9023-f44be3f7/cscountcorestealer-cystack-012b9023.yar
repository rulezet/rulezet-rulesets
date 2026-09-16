rule CSCountCoreStealer_cystack_012b9023
{
    meta:
        family = "CSCountCoreStealer"
        fingerprint_id = "cystack_012b9023"

    strings:
        $key_0 = "Arch:" ascii
        $key_1 = "Count Core:" ascii
        $key_2 = "Hostname:" ascii
        $key_3 = "IP Address:" ascii
        $key_4 = "User Info:" ascii
        $key_5 = "Version:" ascii

    condition:
        all of ($key_*)
}