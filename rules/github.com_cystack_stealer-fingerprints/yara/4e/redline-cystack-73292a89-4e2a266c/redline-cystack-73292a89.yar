rule Redline_cystack_73292a89
{
    meta:
        family = "Redline"
        fingerprint_id = "cystack_73292a89"

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
        $key_10 = "Log date:" ascii
        $key_11 = "Name:" ascii
        $key_12 = "Operation System:" ascii
        $key_13 = "Process Elevation:" ascii
        $key_14 = "ScreenSize:" ascii
        $key_15 = "TimeZone:" ascii
        $key_16 = "UAC:" ascii
        $key_17 = "UserName:" ascii
        $key_18 = "Zip Code:" ascii

    condition:
        all of ($key_*)
}