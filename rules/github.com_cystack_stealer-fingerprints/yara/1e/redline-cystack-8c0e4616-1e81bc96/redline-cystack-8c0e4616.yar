rule Redline_cystack_8c0e4616
{
    meta:
        family = "Redline"
        fingerprint_id = "cystack_8c0e4616"

    strings:
        $key_0 = "Anti-Viruses:" ascii
        $key_1 = "Available KeyboardLayouts:" ascii
        $key_2 = "Build ID:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Current Language:" ascii
        $key_5 = "FileLocation:" ascii
        $key_6 = "HWID:" ascii
        $key_7 = "Hardwares:" ascii
        $key_8 = "IP:" ascii
        $key_9 = "Location:" ascii
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