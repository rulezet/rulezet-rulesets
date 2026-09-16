rule CSHardwareTailStealer_stealercloud
{
    meta:
        family = "CSHardwareTailStealer"
        fingerprint_id = "stealercloud"

    strings:
        $key_0 = "Buy:" ascii
        $key_1 = "New channel:" ascii
        $key_2 = "Reserve Link:" ascii

    condition:
        all of ($key_*)
}