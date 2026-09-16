rule CSStealerCloudUserInfoStealer_stealercloud
{
    meta:
        family = "CSStealerCloudUserInfoStealer"
        fingerprint_id = "stealercloud"

    strings:
        $key_0 = "City:" ascii
        $key_1 = "Country:" ascii
        $key_2 = "Display Resolution:" ascii
        $key_3 = "IP Address:" ascii
        $key_4 = "Keyboard Language:" ascii
        $key_5 = "Postal Code:" ascii
        $key_6 = "Region:" ascii
        $key_7 = "Timezone:" ascii

    condition:
        all of ($key_*)
}