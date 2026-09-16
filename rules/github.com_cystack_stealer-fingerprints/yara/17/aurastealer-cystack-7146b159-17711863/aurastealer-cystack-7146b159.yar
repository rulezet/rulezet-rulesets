rule AuraStealer_cystack_7146b159
{
    meta:
        family = "AuraStealer"
        fingerprint_id = "cystack_7146b159"

    strings:
        $key_0 = "HWID:" ascii
        $key_1 = "Launched at:" ascii
        $key_2 = "Location:" ascii
        $key_3 = "Run as Admin:" ascii
        $key_4 = "Running on:" ascii
        $key_5 = "User in Admins group:" ascii

    condition:
        all of ($key_*)
}