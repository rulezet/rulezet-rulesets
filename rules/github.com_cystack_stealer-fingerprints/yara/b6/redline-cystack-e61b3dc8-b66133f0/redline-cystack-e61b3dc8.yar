rule Redline_cystack_e61b3dc8
{
    meta:
        family = "Redline"
        fingerprint_id = "cystack_e61b3dc8"

    strings:
        $key_0 = "Available KeyboardLayouts:" ascii
        $key_1 = "Current Language:" ascii
        $key_2 = "FileLocation:" ascii
        $key_3 = "HWID:" ascii
        $key_4 = "Hardwares:" ascii
        $key_5 = "IP:" ascii
        $key_6 = "Location:" ascii
        $key_7 = "Log date:" ascii
        $key_8 = "MachineName:" ascii
        $key_9 = "Name:" ascii
        $key_10 = "Operation System:" ascii
        $key_11 = "ScreenSize:" ascii
        $key_12 = "TimeZone:" ascii
        $key_13 = "UserName:" ascii
        $key_14 = "Zip Code:" ascii

    condition:
        all of ($key_*)
}