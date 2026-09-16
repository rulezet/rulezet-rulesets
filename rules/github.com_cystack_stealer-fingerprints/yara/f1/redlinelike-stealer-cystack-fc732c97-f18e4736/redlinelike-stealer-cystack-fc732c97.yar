rule RedlineLike_Stealer_cystack_fc732c97
{
    meta:
        family = "RedlineLike Stealer"
        fingerprint_id = "cystack_fc732c97"

    strings:
        $key_0 = "Computer Name:" ascii
        $key_1 = "Country:" ascii
        $key_2 = "Domain Name:" ascii
        $key_3 = "Graphics card:" ascii
        $key_4 = "HWID:" ascii
        $key_5 = "IP:" ascii
        $key_6 = "Installed RAM:" ascii
        $key_7 = "Log date:" ascii
        $key_8 = "Operation System:" ascii
        $key_9 = "Processor:" ascii
        $key_10 = "System Language:" ascii
        $key_11 = "Traffic:" ascii
        $key_12 = "Version Build:" ascii

    condition:
        all of ($key_*)
}