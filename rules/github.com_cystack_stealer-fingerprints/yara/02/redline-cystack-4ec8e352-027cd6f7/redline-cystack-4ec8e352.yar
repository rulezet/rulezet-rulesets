rule Redline_cystack_4ec8e352
{
    meta:
        family = "Redline"
        fingerprint_id = "cystack_4ec8e352"

    strings:
        $key_0 = "Available KeyboardLayouts:" ascii
        $key_1 = "Country:" ascii
        $key_2 = "Current Language:" ascii
        $key_3 = "FileLocation:" ascii
        $key_4 = "HWID:" ascii
        $key_5 = "Hardwares:" ascii
        $key_6 = "IP:" ascii
        $key_7 = "Name:" ascii
        $key_8 = "Operation System:" ascii
        $key_9 = "Process Elevation:" ascii
        $key_10 = "ScreenSize:" ascii
        $key_11 = "UserName:" ascii
        $key_12 = "Zip Code:" ascii

    condition:
        all of ($key_*)
}