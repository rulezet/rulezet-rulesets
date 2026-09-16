rule CSSigInfoStealer_cystack_7304a1d1
{
    meta:
        family = "CSSigInfoStealer"
        fingerprint_id = "cystack_7304a1d1"

    strings:
        $key_0 = "Country:" ascii
        $key_1 = "IP Address:" ascii
        $key_2 = "Time:" ascii
        $key_3 = "User:" ascii

    condition:
        all of ($key_*)
}