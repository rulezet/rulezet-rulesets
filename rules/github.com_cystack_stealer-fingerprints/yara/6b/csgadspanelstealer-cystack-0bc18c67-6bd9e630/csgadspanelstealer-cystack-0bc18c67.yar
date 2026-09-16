rule CSGADSPanelStealer_cystack_0bc18c67
{
    meta:
        family = "CSGADSPanelStealer"
        fingerprint_id = "cystack_0bc18c67"

    strings:
        $key_0 = "AntiVirus:" ascii
        $key_1 = "Browser Data:" ascii
        $key_2 = "User:" ascii

    condition:
        all of ($key_*)
}