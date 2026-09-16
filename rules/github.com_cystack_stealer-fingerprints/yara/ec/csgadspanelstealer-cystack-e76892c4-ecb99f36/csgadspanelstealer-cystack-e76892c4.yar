rule CSGADSPanelStealer_cystack_e76892c4
{
    meta:
        family = "CSGADSPanelStealer"
        fingerprint_id = "cystack_e76892c4"

    strings:
        $key_0 = "AntiVirus:" ascii
        $key_1 = "Browser Data:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "IP:" ascii
        $key_4 = "User:" ascii

    condition:
        all of ($key_*)
}