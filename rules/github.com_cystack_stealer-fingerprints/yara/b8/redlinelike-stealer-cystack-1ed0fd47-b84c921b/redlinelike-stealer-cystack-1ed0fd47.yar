rule RedlineLike_Stealer_cystack_1ed0fd47
{
    meta:
        family = "RedlineLike Stealer"
        fingerprint_id = "cystack_1ed0fd47"

    strings:
        $key_0 = "BUILD NAME:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Domain Name:" ascii
        $key_4 = "Graphics card:" ascii
        $key_5 = "HWID:" ascii
        $key_6 = "IP:" ascii
        $key_7 = "Installed RAM:" ascii
        $key_8 = "Operation System:" ascii
        $key_9 = "Processor:" ascii
        $key_10 = "Product Key:" ascii
        $key_11 = "Router MAC Address:" ascii
        $key_12 = "System Language:" ascii
        $key_13 = "TimeZone:" ascii

    condition:
        all of ($key_*)
}