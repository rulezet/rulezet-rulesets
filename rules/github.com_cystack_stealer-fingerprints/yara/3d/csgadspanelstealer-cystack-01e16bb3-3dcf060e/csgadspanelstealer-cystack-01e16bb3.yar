rule CSGADSPanelStealer_cystack_01e16bb3
{
    meta:
        family = "CSGADSPanelStealer"
        fingerprint_id = "cystack_01e16bb3"

    strings:
        $key_0 = "Browser Data:" ascii
        $key_1 = "Country:" ascii
        $key_2 = "IP:" ascii
        $key_3 = "User:" ascii

    condition:
        all of ($key_*)
}