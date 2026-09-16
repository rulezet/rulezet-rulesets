rule RedlineLike_Stealer_cystack_be979f63
{
    meta:
        family = "RedlineLike Stealer"
        fingerprint_id = "cystack_be979f63"

    strings:
        $key_0 = "Admin Group:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Display Resolution:" ascii
        $key_3 = "Domain Name:" ascii
        $key_4 = "Graphics card:" ascii
        $key_5 = "Installed RAM:" ascii
        $key_6 = "Integrity:" ascii
        $key_7 = "Keyboard Language:" ascii
        $key_8 = "Log date:" ascii
        $key_9 = "MachineID:" ascii
        $key_10 = "Operation System:" ascii
        $key_11 = "Product Key:" ascii
        $key_12 = "System Language:" ascii
        $key_13 = "TimeZone:" ascii
        $key_14 = "User Name:" ascii
        $key_15 = "UserLanguage:" ascii
        $key_16 = "Wallpaper Hash:" ascii

    condition:
        all of ($key_*)
}