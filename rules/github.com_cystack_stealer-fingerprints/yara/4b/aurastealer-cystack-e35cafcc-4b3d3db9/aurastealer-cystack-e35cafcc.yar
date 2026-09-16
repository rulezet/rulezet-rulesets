rule AuraStealer_cystack_e35cafcc
{
    meta:
        family = "AuraStealer"
        fingerprint_id = "cystack_e35cafcc"

    strings:
        $key_0 = "Launched at:" ascii
        $key_1 = "Location:" ascii
        $key_2 = "Run as Admin:" ascii
        $key_3 = "Running on:" ascii
        $key_4 = "User in Admins group:" ascii

    condition:
        all of ($key_*)
}