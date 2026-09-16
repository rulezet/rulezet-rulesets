rule Vidar_cystack_1d19be11
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_1d19be11"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Bully:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Danganronpa V3:" ascii
        $key_6 = "Date:" ascii
        $key_7 = "Display Resolution:" ascii
        $key_8 = "GUID:" ascii
        $key_9 = "HWID:" ascii
        $key_10 = "Hollow Knight:" ascii
        $key_11 = "Install Date:" ascii
        $key_12 = "Ip:" ascii
        $key_13 = "Keyboard Languages:" ascii
        $key_14 = "Local Time:" ascii
        $key_15 = "MachineID:" ascii
        $key_16 = "Path:" ascii
        $key_17 = "Processor:" ascii
        $key_18 = "RAM:" ascii
        $key_19 = "Threads:" ascii
        $key_20 = "TimeZone:" ascii
        $key_21 = "User Name:" ascii
        $key_22 = "VideoCard:" ascii
        $key_23 = "Windows:" ascii
        $key_24 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}