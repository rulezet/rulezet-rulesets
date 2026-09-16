rule Vidar_cystack_1b55ea1c
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_1b55ea1c"

    strings:
        $key_0 = "ARK:" ascii
        $key_1 = "AV:" ascii
        $key_2 = "Borderlands:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Date:" ascii
        $key_7 = "Display Resolution:" ascii
        $key_8 = "GUID:" ascii
        $key_9 = "HWID:" ascii
        $key_10 = "Install Date:" ascii
        $key_11 = "Ip:" ascii
        $key_12 = "Keyboard Languages:" ascii
        $key_13 = "Kingdom:" ascii
        $key_14 = "Local Time:" ascii
        $key_15 = "MachineID:" ascii
        $key_16 = "Magic:" ascii
        $key_17 = "Path:" ascii
        $key_18 = "Processor:" ascii
        $key_19 = "RAM:" ascii
        $key_20 = "Threads:" ascii
        $key_21 = "TimeZone:" ascii
        $key_22 = "User Name:" ascii
        $key_23 = "VideoCard:" ascii
        $key_24 = "Windows:" ascii
        $key_25 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}