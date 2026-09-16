rule Vidar_cystack_0d93612d
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_0d93612d"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Date:" ascii
        $key_5 = "Display Resolution:" ascii
        $key_6 = "GUID:" ascii
        $key_7 = "HWID:" ascii
        $key_8 = "Install Date:" ascii
        $key_9 = "Ip:" ascii
        $key_10 = "Keyboard Languages:" ascii
        $key_11 = "Local Time:" ascii
        $key_12 = "MachineID:" ascii
        $key_13 = "Ocean World:" ascii
        $key_14 = "Offroad Mechanic Simulator:" ascii
        $key_15 = "Path:" ascii
        $key_16 = "Processor:" ascii
        $key_17 = "RAM:" ascii
        $key_18 = "Threads:" ascii
        $key_19 = "TimeZone:" ascii
        $key_20 = "User Name:" ascii
        $key_21 = "VideoCard:" ascii
        $key_22 = "Windows:" ascii
        $key_23 = "Work Dir:" ascii
        $key_24 = "Zoo Simulator:" ascii

    condition:
        all of ($key_*)
}