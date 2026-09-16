rule Vidar_cystack_248d6d62
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_248d6d62"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Banana Hell:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "GUID:" ascii
        $key_8 = "HWID:" ascii
        $key_9 = "Install Date:" ascii
        $key_10 = "Ip:" ascii
        $key_11 = "Keyboard Languages:" ascii
        $key_12 = "Local Time:" ascii
        $key_13 = "MachineID:" ascii
        $key_14 = "My Femboy Roommate:" ascii
        $key_15 = "Path:" ascii
        $key_16 = "Processor:" ascii
        $key_17 = "RAM:" ascii
        $key_18 = "Threads:" ascii
        $key_19 = "TimeZone:" ascii
        $key_20 = "User Name:" ascii
        $key_21 = "VideoCard:" ascii
        $key_22 = "Windows:" ascii
        $key_23 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}