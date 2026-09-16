rule RedlineLike_Stealer_cystack_67d5e1ab
{
    meta:
        family = "RedlineLike Stealer"
        fingerprint_id = "cystack_67d5e1ab"

    strings:
        $key_0 = "Admin Group:" ascii
        $key_1 = "Antivirus:" ascii
        $key_2 = "City:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Display Resolution:" ascii
        $key_6 = "Domain Name:" ascii
        $key_7 = "Graphics card:" ascii
        $key_8 = "IP Address:" ascii
        $key_9 = "Installed RAM:" ascii
        $key_10 = "Integrity:" ascii
        $key_11 = "Keyboard Language:" ascii
        $key_12 = "Operation System:" ascii
        $key_13 = "Postal Code:" ascii
        $key_14 = "Processor:" ascii
        $key_15 = "Region:" ascii
        $key_16 = "TimeZone:" ascii
        $key_17 = "Timezone:" ascii
        $key_18 = "User Name:" ascii
        $key_19 = "UserLanguage:" ascii

    condition:
        all of ($key_*)
}