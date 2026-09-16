rule RedlineLike_Stealer_cystack_83c06639
{
    meta:
        family = "RedlineLike Stealer"
        fingerprint_id = "cystack_83c06639"

    strings:
        $key_0 = "Admin Group:" ascii
        $key_1 = "Country:" ascii
        $key_2 = "Display Resolution:" ascii
        $key_3 = "Domain Name:" ascii
        $key_4 = "Graphics card:" ascii
        $key_5 = "HWID:" ascii
        $key_6 = "IP:" ascii
        $key_7 = "Installed RAM:" ascii
        $key_8 = "Integrity:" ascii
        $key_9 = "Keyboard Language:" ascii
        $key_10 = "Log date:" ascii
        $key_11 = "MachineID:" ascii
        $key_12 = "Operation System:" ascii
        $key_13 = "Processor:" ascii
        $key_14 = "System Language:" ascii
        $key_15 = "TimeZone:" ascii
        $key_16 = "User Name:" ascii
        $key_17 = "UserLanguage:" ascii
        $key_18 = "Wallpaper Hash:" ascii

    condition:
        all of ($key_*)
}