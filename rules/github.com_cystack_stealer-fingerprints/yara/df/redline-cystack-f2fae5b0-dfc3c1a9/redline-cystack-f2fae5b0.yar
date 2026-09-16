rule Redline_cystack_f2fae5b0
{
    meta:
        family = "Redline"
        fingerprint_id = "cystack_f2fae5b0"

    strings:
        $key_0 = "Available KeyboardLayouts:" ascii
        $key_1 = "Country:" ascii
        $key_2 = "Current Language:" ascii
        $key_3 = "FileLocation:" ascii
        $key_4 = "HWID:" ascii
        $key_5 = "Hardwares:" ascii
        $key_6 = "IP:" ascii
        $key_7 = "Location:" ascii
        $key_8 = "Log date:" ascii
        $key_9 = "MachineName:" ascii
        $key_10 = "Operation System:" ascii
        $key_11 = "ScreenSize:" ascii
        $key_12 = "TimeZone:" ascii
        $key_13 = "UserName:" ascii
        $key_14 = "Zip Code:" ascii

    condition:
        all of ($key_*)
}