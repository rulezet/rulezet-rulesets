rule CSMacUserinfoStealer_cystack_5d07c49b
{
    meta:
        family = "CSMacUserinfoStealer"
        fingerprint_id = "cystack_5d07c49b"

    strings:
        $key_0 = "Board-ID:" ascii
        $key_1 = "City:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Country Code:" ascii
        $key_4 = "Graphics/Displays:" ascii
        $key_5 = "Hardware:" ascii
        $key_6 = "IP:" ascii
        $key_7 = "Latitude:" ascii
        $key_8 = "Longitude:" ascii
        $key_9 = "Region:" ascii
        $key_10 = "Software:" ascii
        $key_11 = "Timezone:" ascii
        $key_12 = "Zipcode:" ascii

    condition:
        all of ($key_*)
}