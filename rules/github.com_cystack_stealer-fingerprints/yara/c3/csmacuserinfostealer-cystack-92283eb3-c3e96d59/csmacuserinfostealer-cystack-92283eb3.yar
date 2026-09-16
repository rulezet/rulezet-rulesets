rule CSMacUserinfoStealer_cystack_92283eb3
{
    meta:
        family = "CSMacUserinfoStealer"
        fingerprint_id = "cystack_92283eb3"

    strings:
        $key_0 = "City:" ascii
        $key_1 = "Country:" ascii
        $key_2 = "Country Code:" ascii
        $key_3 = "Hardware:" ascii
        $key_4 = "IP:" ascii
        $key_5 = "Latitude:" ascii
        $key_6 = "Longitude:" ascii
        $key_7 = "Region:" ascii
        $key_8 = "Software:" ascii
        $key_9 = "Timezone:" ascii
        $key_10 = "Zipcode:" ascii

    condition:
        all of ($key_*)
}