rule CSGADSPanelStealer_cystack_b723275e
{
    meta:
        family = "CSGADSPanelStealer"
        fingerprint_id = "cystack_b723275e"

    strings:
        $key_0 = "Antivirus:" ascii
        $key_1 = "Browser Data:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "IP:" ascii
        $key_4 = "RuntimeExecption:" ascii
        $key_5 = "User:" ascii

    condition:
        all of ($key_*)
}