rule RedlineLike_Stealer_cystack_c1e6a3a7
{
    meta:
        family = "RedlineLike Stealer"
        fingerprint_id = "cystack_c1e6a3a7"

    strings:
        $key_0 = "Admin Group:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Display Resolution:" ascii
        $key_4 = "Domain Name:" ascii
        $key_5 = "Graphics card:" ascii
        $key_6 = "HWID:" ascii
        $key_7 = "IP:" ascii
        $key_8 = "Installed RAM:" ascii
        $key_9 = "Integrity:" ascii
        $key_10 = "Keyboard Language:" ascii
        $key_11 = "Log date:" ascii
        $key_12 = "MachineID:" ascii
        $key_13 = "Operation System:" ascii
        $key_14 = "Processor:" ascii
        $key_15 = "Product Key:" ascii
        $key_16 = "System Language:" ascii
        $key_17 = "TimeZone:" ascii
        $key_18 = "UserLanguage:" ascii
        $key_19 = "Wallpaper Hash:" ascii

    condition:
        all of ($key_*)
}