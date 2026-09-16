rule RedlineLike_Stealer_cystack_fddd76ee
{
    meta:
        family = "RedlineLike Stealer"
        fingerprint_id = "cystack_fddd76ee"

    strings:
        $key_0 = "Admin Group:" ascii
        $key_1 = "BUILD NAME:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Display Resolution:" ascii
        $key_5 = "Domain Name:" ascii
        $key_6 = "Graphics card:" ascii
        $key_7 = "IP:" ascii
        $key_8 = "Installed RAM:" ascii
        $key_9 = "Integrity:" ascii
        $key_10 = "Keyboard Language:" ascii
        $key_11 = "Operation System:" ascii
        $key_12 = "Router MAC Address:" ascii
        $key_13 = "System Language:" ascii
        $key_14 = "TimeZone:" ascii
        $key_15 = "User Name:" ascii
        $key_16 = "UserLanguage:" ascii
        $key_17 = "Wallpaper Hash:" ascii

    condition:
        all of ($key_*)
}