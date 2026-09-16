rule Redline_cystack_e9a53ad6
{
    meta:
        family = "Redline"
        fingerprint_id = "cystack_e9a53ad6"

    strings:
        $key_0 = "Anti-Viruses:" ascii
        $key_1 = "Available KeyboardLayouts:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Current Language:" ascii
        $key_4 = "FileLocation:" ascii
        $key_5 = "HWID:" ascii
        $key_6 = "Hardwares:" ascii
        $key_7 = "IP:" ascii
        $key_8 = "Name:" ascii
        $key_9 = "Operation System:" ascii
        $key_10 = "Process Elevation:" ascii
        $key_11 = "ScreenSize:" ascii
        $key_12 = "TimeZone:" ascii
        $key_13 = "UserName:" ascii
        $key_14 = "Zip Code:" ascii

    condition:
        all of ($key_*)
}