rule CSGADSPanelStealer_cystack_7c0940cc
{
    meta:
        family = "CSGADSPanelStealer"
        fingerprint_id = "cystack_7c0940cc"

    strings:
        $key_0 = "Browser Data:" ascii
        $key_1 = "Country:" ascii
        $key_2 = "User:" ascii

    condition:
        all of ($key_*)
}