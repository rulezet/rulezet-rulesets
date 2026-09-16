rule RedlineLike_Stealer_cystack_a06e8d9d
{
    meta:
        family = "RedlineLike Stealer"
        fingerprint_id = "cystack_a06e8d9d"

    strings:
        $key_0 = "Admin Group:" ascii
        $key_1 = "Antivirus:" ascii
        $key_2 = "City:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Display Resolution:" ascii
        $key_6 = "Domain Name:" ascii
        $key_7 = "Graphics card:" ascii
        $key_8 = "HWID:" ascii
        $key_9 = "IP Address:" ascii
        $key_10 = "Installed RAM:" ascii
        $key_11 = "Integrity:" ascii
        $key_12 = "Keyboard Language:" ascii
        $key_13 = "Log date:" ascii
        $key_14 = "Operation System:" ascii
        $key_15 = "Postal Code:" ascii
        $key_16 = "Processor:" ascii
        $key_17 = "Region:" ascii
        $key_18 = "System Language:" ascii
        $key_19 = "TimeZone:" ascii
        $key_20 = "Timezone:" ascii
        $key_21 = "User Name:" ascii
        $key_22 = "UserLanguage:" ascii
        $key_23 = "Wallpaper Hash:" ascii

    condition:
        all of ($key_*)
}