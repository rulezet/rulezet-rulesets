rule CSUsersListStealer_bradmax
{
    meta:
        family = "CSUsersListStealer"
        fingerprint_id = "bradmax"

    strings:
        $key_0 = "HWID:" ascii
        $key_1 = "IP:" ascii
        $key_2 = "Users:" ascii

    condition:
        all of ($key_*)
}