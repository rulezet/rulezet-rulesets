rule RedlineLike_Stealer_cystack_cfd0ac77
{
    meta:
        family = "RedlineLike Stealer"
        fingerprint_id = "cystack_cfd0ac77"

    strings:
        $key_0 = "City:" ascii
        $key_1 = "Country:" ascii
        $key_2 = "Display Resolution:" ascii
        $key_3 = "IP Address:" ascii
        $key_4 = "Keyboard Language:" ascii
        $key_5 = "Postal Code:" ascii
        $key_6 = "Region:" ascii
        $key_7 = "TimeZone:" ascii
        $key_8 = "Timezone:" ascii
        $key_9 = "UserLanguage:" ascii

    condition:
        all of ($key_*)
}