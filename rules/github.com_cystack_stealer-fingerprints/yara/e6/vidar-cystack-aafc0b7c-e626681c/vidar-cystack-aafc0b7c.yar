rule Vidar_cystack_aafc0b7c
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_aafc0b7c"

    strings:
        $key_0 = "CPU Count:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Date:" ascii
        $key_3 = "Display Language:" ascii
        $key_4 = "Display Resolution:" ascii
        $key_5 = "GUID:" ascii
        $key_6 = "HWID:" ascii
        $key_7 = "IP:" ascii
        $key_8 = "Keyboard Languages:" ascii
        $key_9 = "Local Time:" ascii
        $key_10 = "Location:" ascii
        $key_11 = "MachineID:" ascii
        $key_12 = "Path:" ascii
        $key_13 = "Processor:" ascii
        $key_14 = "QuickBooks Premier:" ascii
        $key_15 = "RAM:" ascii
        $key_16 = "TimeZone:" ascii
        $key_17 = "User Name:" ascii
        $key_18 = "Version:" ascii
        $key_19 = "Windows:" ascii
        $key_20 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}