rule RedlineLike_Stealer_cystack_32be75b7
{
    meta:
        family = "RedlineLike Stealer"
        fingerprint_id = "cystack_32be75b7"

    strings:
        $key_0 = "APPLE:" ascii
        $key_1 = "Admin Group:" ascii
        $key_2 = "BUILD NAME:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Display Resolution:" ascii
        $key_6 = "Domain Name:" ascii
        $key_7 = "Graphics card:" ascii
        $key_8 = "HWID:" ascii
        $key_9 = "IP:" ascii
        $key_10 = "Installed RAM:" ascii
        $key_11 = "Integrity:" ascii
        $key_12 = "Keyboard Language:" ascii
        $key_13 = "Operation System:" ascii
        $key_14 = "Processor:" ascii
        $key_15 = "Product Key:" ascii
        $key_16 = "Router MAC Address:" ascii
        $key_17 = "System Language:" ascii
        $key_18 = "TimeZone:" ascii
        $key_19 = "User Name:" ascii
        $key_20 = "UserLanguage:" ascii
        $key_21 = "Wallpaper Hash:" ascii

    condition:
        all of ($key_*)
}