rule CSDashPlusSepStealer_bradmax
{
    meta:
        family = "CSDashPlusSepStealer"
        fingerprint_id = "bradmax"

    strings:
        $key_0 = "CK:" ascii
        $key_1 = "ID:" ascii
        $key_2 = "Username:" ascii

    condition:
        all of ($key_*)
}