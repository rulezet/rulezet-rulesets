rule CSPyHostTimeStealer_bradmax
{
    meta:
        family = "CSPyHostTimeStealer"
        fingerprint_id = "bradmax"

    strings:
        $key_0 = "Host:" ascii
        $key_1 = "OS:" ascii
        $key_2 = "Time:" ascii

    condition:
        all of ($key_*)
}