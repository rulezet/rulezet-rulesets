rule CSMrdUidStealer_cystack_7c108e60
{
    meta:
        family = "CSMrdUidStealer"
        fingerprint_id = "cystack_7c108e60"

    strings:
        $key_0 = "CPU:" ascii
        $key_1 = "ComputerName:" ascii
        $key_2 = "DateTime:" ascii
        $key_3 = "Disk:" ascii
        $key_4 = "Display Resolution:" ascii
        $key_5 = "GPU:" ascii
        $key_6 = "Installed software:" ascii
        $key_7 = "Keyboard Languages:" ascii
        $key_8 = "OS:" ascii
        $key_9 = "Process:" ascii
        $key_10 = "RAM:" ascii
        $key_11 = "UID:" ascii
        $key_12 = "UserAgent:" ascii
        $key_13 = "UserName:" ascii

    condition:
        all of ($key_*)
}