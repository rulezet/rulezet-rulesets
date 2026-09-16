rule CSSigInfoStealer_cystack_d41e9f17
{
    meta:
        family = "CSSigInfoStealer"
        fingerprint_id = "cystack_d41e9f17"

    strings:
        $key_0 = "Country:" ascii
        $key_1 = "Database Name:" ascii
        $key_2 = "IP Address:" ascii
        $key_3 = "Project Name:" ascii
        $key_4 = "Time:" ascii
        $key_5 = "User:" ascii
        $key_6 = "User Name:" ascii

    condition:
        all of ($key_*)
}