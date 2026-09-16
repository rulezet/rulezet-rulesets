rule RedlineLike_Stealer_cystack_98fabc58
{
    meta:
        family = "RedlineLike Stealer"
        fingerprint_id = "cystack_98fabc58"

    strings:
        $key_0 = "Computer Name:" ascii
        $key_1 = "Country:" ascii
        $key_2 = "Domain Name:" ascii
        $key_3 = "Graphics card:" ascii
        $key_4 = "IP:" ascii
        $key_5 = "Installed RAM:" ascii
        $key_6 = "MachineID:" ascii
        $key_7 = "Operation System:" ascii
        $key_8 = "Processor:" ascii
        $key_9 = "Product Key:" ascii
        $key_10 = "System Language:" ascii

    condition:
        all of ($key_*)
}