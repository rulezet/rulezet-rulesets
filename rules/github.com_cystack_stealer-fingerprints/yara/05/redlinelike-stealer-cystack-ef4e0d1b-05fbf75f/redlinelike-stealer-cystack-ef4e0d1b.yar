rule RedlineLike_Stealer_cystack_ef4e0d1b
{
    meta:
        family = "RedlineLike Stealer"
        fingerprint_id = "cystack_ef4e0d1b"

    strings:
        $key_0 = "Admin Group:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Display Resolution:" ascii
        $key_3 = "Domain Name:" ascii
        $key_4 = "Graphics card:" ascii
        $key_5 = "IP:" ascii
        $key_6 = "Installed RAM:" ascii
        $key_7 = "Integrity:" ascii
        $key_8 = "Keyboard Language:" ascii
        $key_9 = "MachineID:" ascii
        $key_10 = "Operation System:" ascii
        $key_11 = "Processor:" ascii
        $key_12 = "Product Key:" ascii
        $key_13 = "System Language:" ascii
        $key_14 = "TimeZone:" ascii
        $key_15 = "User Name:" ascii
        $key_16 = "UserLanguage:" ascii

    condition:
        all of ($key_*)
}