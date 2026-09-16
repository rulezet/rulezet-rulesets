rule Redline_cystack_84cd011a
{
    meta:
        family = "Redline"
        fingerprint_id = "cystack_84cd011a"

    strings:
        $key_0 = "Available KeyboardLayouts:" ascii
        $key_1 = "Build ID:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Current Language:" ascii
        $key_4 = "FileLocation:" ascii
        $key_5 = "HWID:" ascii
        $key_6 = "Hardwares:" ascii
        $key_7 = "IP:" ascii
        $key_8 = "Location:" ascii
        $key_9 = "Log date:" ascii
        $key_10 = "Name:" ascii
        $key_11 = "Operation System:" ascii
        $key_12 = "Process Elevation:" ascii
        $key_13 = "ScreenSize:" ascii
        $key_14 = "TimeZone:" ascii
        $key_15 = "UAC:" ascii
        $key_16 = "UserName:" ascii
        $key_17 = "Zip Code:" ascii

    condition:
        all of ($key_*)
}