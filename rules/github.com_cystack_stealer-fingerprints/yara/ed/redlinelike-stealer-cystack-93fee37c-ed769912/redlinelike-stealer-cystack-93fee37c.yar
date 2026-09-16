rule RedlineLike_Stealer_cystack_93fee37c
{
    meta:
        family = "RedlineLike Stealer"
        fingerprint_id = "cystack_93fee37c"

    strings:
        $key_0 = "Admin Group:" ascii
        $key_1 = "BUILD NAME:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Display Resolution:" ascii
        $key_5 = "Domain Name:" ascii
        $key_6 = "Graphics card:" ascii
        $key_7 = "HWID:" ascii
        $key_8 = "IP:" ascii
        $key_9 = "Installed RAM:" ascii
        $key_10 = "Integrity:" ascii
        $key_11 = "Keyboard Language:" ascii
        $key_12 = "Operation System:" ascii
        $key_13 = "Processor:" ascii
        $key_14 = "Product Key:" ascii
        $key_15 = "Router MAC Address:" ascii
        $key_16 = "System Language:" ascii
        $key_17 = "TimeZone:" ascii
        $key_18 = "User Name:" ascii
        $key_19 = "UserLanguage:" ascii
        $key_20 = "Wallpaper Hash:" ascii

    condition:
        all of ($key_*)
}