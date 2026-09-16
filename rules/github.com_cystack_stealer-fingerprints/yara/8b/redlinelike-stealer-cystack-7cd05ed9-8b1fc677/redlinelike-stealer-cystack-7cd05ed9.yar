rule RedlineLike_Stealer_cystack_7cd05ed9
{
    meta:
        family = "RedlineLike Stealer"
        fingerprint_id = "cystack_7cd05ed9"

    strings:
        $key_0 = "APPLE:" ascii
        $key_1 = "Admin Group:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Display Resolution:" ascii
        $key_5 = "Domain Name:" ascii
        $key_6 = "GOOGLE:" ascii
        $key_7 = "Graphics card:" ascii
        $key_8 = "HWID:" ascii
        $key_9 = "IP:" ascii
        $key_10 = "Installed RAM:" ascii
        $key_11 = "Integrity:" ascii
        $key_12 = "Keyboard Language:" ascii
        $key_13 = "Operation System:" ascii
        $key_14 = "Processor:" ascii
        $key_15 = "Product Key:" ascii
        $key_16 = "Router MAC Address:" ascii
        $key_17 = "System Language:" ascii
        $key_18 = "TimeZone:" ascii
        $key_19 = "User Name:" ascii
        $key_20 = "UserLanguage:" ascii

    condition:
        all of ($key_*)
}