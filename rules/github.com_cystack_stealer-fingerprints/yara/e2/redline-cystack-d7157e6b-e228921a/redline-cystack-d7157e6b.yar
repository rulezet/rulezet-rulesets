rule Redline_cystack_d7157e6b
{
    meta:
        family = "Redline"
        fingerprint_id = "cystack_d7157e6b"

    strings:
        $key_0 = "Build ID:" ascii
        $key_1 = "Country:" ascii
        $key_2 = "Current Language:" ascii
        $key_3 = "FileLocation:" ascii
        $key_4 = "HWID:" ascii
        $key_5 = "IP:" ascii
        $key_6 = "Location:" ascii
        $key_7 = "Log date:" ascii
        $key_8 = "Operation System:" ascii
        $key_9 = "Process Elevation:" ascii
        $key_10 = "ScreenSize:" ascii
        $key_11 = "TimeZone:" ascii
        $key_12 = "UAC:" ascii
        $key_13 = "UserName:" ascii
        $key_14 = "Zip Code:" ascii

    condition:
        all of ($key_*)
}