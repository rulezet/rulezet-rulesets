rule Redline_cystack_ad806f89
{
    meta:
        family = "Redline"
        fingerprint_id = "cystack_ad806f89"

    strings:
        $key_0 = "Anti-Viruses:" ascii
        $key_1 = "Available KeyboardLayouts:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Current Language:" ascii
        $key_4 = "FileLocation:" ascii
        $key_5 = "Hardwares:" ascii
        $key_6 = "IP:" ascii
        $key_7 = "Location:" ascii
        $key_8 = "Log date:" ascii
        $key_9 = "Name:" ascii
        $key_10 = "Operation System:" ascii
        $key_11 = "Process Elevation:" ascii
        $key_12 = "ScreenSize:" ascii
        $key_13 = "TimeZone:" ascii
        $key_14 = "UserName:" ascii
        $key_15 = "Zip Code:" ascii

    condition:
        all of ($key_*)
}