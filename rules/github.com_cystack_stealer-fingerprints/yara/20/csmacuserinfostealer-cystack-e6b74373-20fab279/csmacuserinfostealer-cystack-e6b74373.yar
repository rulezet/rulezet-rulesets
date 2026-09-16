rule CSMacUserinfoStealer_cystack_e6b74373
{
    meta:
        family = "CSMacUserinfoStealer"
        fingerprint_id = "cystack_e6b74373"

    strings:
        $key_0 = "City:" ascii
        $key_1 = "Country:" ascii
        $key_2 = "Country Code:" ascii
        $key_3 = "Graphics/Displays:" ascii
        $key_4 = "Hardware:" ascii
        $key_5 = "IP:" ascii
        $key_6 = "Latitude:" ascii
        $key_7 = "Longitude:" ascii
        $key_8 = "Region:" ascii
        $key_9 = "Software:" ascii
        $key_10 = "Timezone:" ascii
        $key_11 = "Zipcode:" ascii

    condition:
        all of ($key_*)
}