rule Redline_cystack_b95b940e
{
    meta:
        family = "Redline"
        fingerprint_id = "cystack_b95b940e"

    strings:
        $key_0 = "Anti-Viruses:" ascii
        $key_1 = "Available KeyboardLayouts:" ascii
        $key_2 = "Build ID:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Current Language:" ascii
        $key_5 = "FileLocation:" ascii
        $key_6 = "HWID:" ascii
        $key_7 = "IP:" ascii
        $key_8 = "Location:" ascii
        $key_9 = "Log date:" ascii
        $key_10 = "Operation System:" ascii
        $key_11 = "Process Elevation:" ascii
        $key_12 = "ScreenSize:" ascii
        $key_13 = "TimeZone:" ascii
        $key_14 = "UAC:" ascii
        $key_15 = "UserName:" ascii
        $key_16 = "Zip Code:" ascii

    condition:
        all of ($key_*)
}