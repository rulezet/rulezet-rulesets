rule CSMacBareGeoStealer_cystack_9e4fa79f
{
    meta:
        family = "CSMacBareGeoStealer"
        fingerprint_id = "cystack_9e4fa79f"

    strings:
        $key_0 = "Country:" ascii
        $key_1 = "Graphics/Displays:" ascii
        $key_2 = "Hardware:" ascii
        $key_3 = "IP:" ascii
        $key_4 = "Software:" ascii

    condition:
        all of ($key_*)
}