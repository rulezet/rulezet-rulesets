rule CSGADSPanelStealer_cystack_8479d801
{
    meta:
        family = "CSGADSPanelStealer"
        fingerprint_id = "cystack_8479d801"

    strings:
        $key_0 = "AntiVirus:" ascii
        $key_1 = "Browser Data:" ascii
        $key_2 = "IP:" ascii
        $key_3 = "User:" ascii

    condition:
        all of ($key_*)
}