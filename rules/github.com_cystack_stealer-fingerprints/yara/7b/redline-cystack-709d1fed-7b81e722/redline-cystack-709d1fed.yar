rule Redline_cystack_709d1fed
{
    meta:
        family = "Redline"
        fingerprint_id = "cystack_709d1fed"

    strings:
        $key_0 = "Build ID:" ascii
        $key_1 = "Country:" ascii
        $key_2 = "Current Language:" ascii
        $key_3 = "FileLocation:" ascii
        $key_4 = "HWID:" ascii
        $key_5 = "Hardwares:" ascii
        $key_6 = "IP:" ascii
        $key_7 = "Location:" ascii
        $key_8 = "Log date:" ascii
        $key_9 = "Name:" ascii
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