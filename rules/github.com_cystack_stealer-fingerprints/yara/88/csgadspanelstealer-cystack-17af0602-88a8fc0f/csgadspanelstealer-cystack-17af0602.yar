rule CSGADSPanelStealer_cystack_17af0602
{
    meta:
        family = "CSGADSPanelStealer"
        fingerprint_id = "cystack_17af0602"

    strings:
        $key_0 = "AntiVirus:" ascii
        $key_1 = "Browser Data:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Ip:" ascii
        $key_4 = "User:" ascii

    condition:
        all of ($key_*)
}