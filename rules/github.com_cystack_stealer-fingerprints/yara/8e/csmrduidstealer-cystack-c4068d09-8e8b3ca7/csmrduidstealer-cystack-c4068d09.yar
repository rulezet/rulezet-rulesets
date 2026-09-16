rule CSMrdUidStealer_cystack_c4068d09
{
    meta:
        family = "CSMrdUidStealer"
        fingerprint_id = "cystack_c4068d09"

    strings:
        $key_0 = "CPU:" ascii
        $key_1 = "ComputerName:" ascii
        $key_2 = "DateTime:" ascii
        $key_3 = "Display Resolution:" ascii
        $key_4 = "GPU:" ascii
        $key_5 = "Installed software:" ascii
        $key_6 = "Keyboard Languages:" ascii
        $key_7 = "OS:" ascii
        $key_8 = "RAM:" ascii
        $key_9 = "UID:" ascii
        $key_10 = "UserAgent:" ascii
        $key_11 = "UserName:" ascii

    condition:
        all of ($key_*)
}