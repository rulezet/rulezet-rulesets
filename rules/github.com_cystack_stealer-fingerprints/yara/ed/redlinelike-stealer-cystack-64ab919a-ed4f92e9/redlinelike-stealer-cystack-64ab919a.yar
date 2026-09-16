rule RedlineLike_Stealer_cystack_64ab919a
{
    meta:
        family = "RedlineLike Stealer"
        fingerprint_id = "cystack_64ab919a"

    strings:
        $key_0 = "Admin Group:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Display Resolution:" ascii
        $key_4 = "Domain Name:" ascii
        $key_5 = "Graphics card:" ascii
        $key_6 = "IP:" ascii
        $key_7 = "Installed RAM:" ascii
        $key_8 = "Integrity:" ascii
        $key_9 = "Keyboard Language:" ascii
        $key_10 = "Log date:" ascii
        $key_11 = "MachineID:" ascii
        $key_12 = "Operation System:" ascii
        $key_13 = "Processor:" ascii
        $key_14 = "Product Key:" ascii
        $key_15 = "System Language:" ascii
        $key_16 = "TimeZone:" ascii
        $key_17 = "Traffic:" ascii
        $key_18 = "UserLanguage:" ascii
        $key_19 = "Wallpaper Hash:" ascii

    condition:
        all of ($key_*)
}