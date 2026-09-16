rule RedlineLike_Stealer_cystack_3ffbbc4b
{
    meta:
        family = "RedlineLike Stealer"
        fingerprint_id = "cystack_3ffbbc4b"

    strings:
        $key_0 = "Admin Group:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Display Resolution:" ascii
        $key_3 = "Domain Name:" ascii
        $key_4 = "Graphics card:" ascii
        $key_5 = "Integrity:" ascii
        $key_6 = "Keyboard Language:" ascii
        $key_7 = "Log date:" ascii
        $key_8 = "MachineID:" ascii
        $key_9 = "Operation System:" ascii
        $key_10 = "Processor:" ascii
        $key_11 = "Product Key:" ascii
        $key_12 = "TimeZone:" ascii
        $key_13 = "User Name:" ascii
        $key_14 = "UserLanguage:" ascii
        $key_15 = "Wallpaper Hash:" ascii

    condition:
        all of ($key_*)
}