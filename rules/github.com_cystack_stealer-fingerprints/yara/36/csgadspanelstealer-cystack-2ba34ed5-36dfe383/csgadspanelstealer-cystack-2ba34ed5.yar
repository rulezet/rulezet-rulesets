rule CSGADSPanelStealer_cystack_2ba34ed5
{
    meta:
        family = "CSGADSPanelStealer"
        fingerprint_id = "cystack_2ba34ed5"

    strings:
        $key_0 = "AntiVirus:" ascii
        $key_1 = "Browser Data:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "User:" ascii

    condition:
        all of ($key_*)
}