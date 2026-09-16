rule RedlineLike_Stealer_cystack_d7d05872
{
    meta:
        family = "RedlineLike Stealer"
        fingerprint_id = "cystack_d7d05872"

    strings:
        $key_0 = "Admin Group:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Display Resolution:" ascii
        $key_4 = "Domain Name:" ascii
        $key_5 = "Graphics card:" ascii
        $key_6 = "HWID:" ascii
        $key_7 = "IP:" ascii
        $key_8 = "Installed RAM:" ascii
        $key_9 = "Integrity:" ascii
        $key_10 = "Keyboard Language:" ascii
        $key_11 = "Operation System:" ascii
        $key_12 = "Processor:" ascii
        $key_13 = "Product Key:" ascii
        $key_14 = "Router MAC Address:" ascii
        $key_15 = "System Language:" ascii
        $key_16 = "TimeZone:" ascii
        $key_17 = "User Name:" ascii
        $key_18 = "UserLanguage:" ascii

    condition:
        all of ($key_*)
}