rule RedlineLike_Stealer_cystack_e9c9d718
{
    meta:
        family = "RedlineLike Stealer"
        fingerprint_id = "cystack_e9c9d718"

    strings:
        $key_0 = "Country:" ascii
        $key_1 = "Graphics card:" ascii
        $key_2 = "HWID:" ascii
        $key_3 = "IP:" ascii
        $key_4 = "Installed RAM:" ascii
        $key_5 = "Log date:" ascii
        $key_6 = "Operation System:" ascii
        $key_7 = "Processor:" ascii
        $key_8 = "System Language:" ascii
        $key_9 = "Traffic:" ascii
        $key_10 = "Version Build:" ascii

    condition:
        all of ($key_*)
}