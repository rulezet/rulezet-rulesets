rule RedlineLike_Stealer_cystack_4d65acc2
{
    meta:
        family = "RedlineLike Stealer"
        fingerprint_id = "cystack_4d65acc2"

    strings:
        $key_0 = "Admin Group:" ascii
        $key_1 = "Display Resolution:" ascii
        $key_2 = "Integrity:" ascii
        $key_3 = "Keyboard Language:" ascii
        $key_4 = "TimeZone:" ascii
        $key_5 = "UserLanguage:" ascii

    condition:
        all of ($key_*)
}