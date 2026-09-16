rule Redline_cystack_73218974
{
    meta:
        family = "Redline"
        fingerprint_id = "cystack_73218974"

    strings:
        $key_0 = "Available KeyboardLayouts:" ascii
        $key_1 = "Build ID:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Current Language:" ascii
        $key_4 = "FileLocation:" ascii
        $key_5 = "HWID:" ascii
        $key_6 = "IP:" ascii
        $key_7 = "Location:" ascii
        $key_8 = "Log date:" ascii
        $key_9 = "Operation System:" ascii
        $key_10 = "Process Elevation:" ascii
        $key_11 = "ScreenSize:" ascii
        $key_12 = "TimeZone:" ascii
        $key_13 = "UAC:" ascii
        $key_14 = "UserName:" ascii
        $key_15 = "Zip Code:" ascii

    condition:
        all of ($key_*)
}