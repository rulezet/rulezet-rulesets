rule RedlineLike_Stealer_cystack_133f0f19
{
    meta:
        family = "RedlineLike Stealer"
        fingerprint_id = "cystack_133f0f19"

    strings:
        $key_0 = "APPLE:" ascii
        $key_1 = "Admin Group:" ascii
        $key_2 = "BUILD NAME:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Display Resolution:" ascii
        $key_6 = "Domain Name:" ascii
        $key_7 = "GOOGLE:" ascii
        $key_8 = "Graphics card:" ascii
        $key_9 = "HWID:" ascii
        $key_10 = "IP:" ascii
        $key_11 = "Installed RAM:" ascii
        $key_12 = "Integrity:" ascii
        $key_13 = "Keyboard Language:" ascii
        $key_14 = "Operation System:" ascii
        $key_15 = "Processor:" ascii
        $key_16 = "Product Key:" ascii
        $key_17 = "Router MAC Address:" ascii
        $key_18 = "System Language:" ascii
        $key_19 = "TimeZone:" ascii
        $key_20 = "User Name:" ascii
        $key_21 = "UserLanguage:" ascii

    condition:
        all of ($key_*)
}