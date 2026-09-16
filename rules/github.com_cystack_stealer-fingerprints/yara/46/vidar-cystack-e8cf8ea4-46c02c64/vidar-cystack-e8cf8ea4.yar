rule Vidar_cystack_e8cf8ea4
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_e8cf8ea4"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Cinemaster:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Corner Kitchen:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "GUID:" ascii
        $key_8 = "HWID:" ascii
        $key_9 = "Install Date:" ascii
        $key_10 = "Ip:" ascii
        $key_11 = "Local Time:" ascii
        $key_12 = "MachineID:" ascii
        $key_13 = "Nymphomaniac:" ascii
        $key_14 = "Path:" ascii
        $key_15 = "Police Simulator:" ascii
        $key_16 = "Processor:" ascii
        $key_17 = "RAM:" ascii
        $key_18 = "Threads:" ascii
        $key_19 = "TimeZone:" ascii
        $key_20 = "User Name:" ascii
        $key_21 = "Version:" ascii
        $key_22 = "VideoCard:" ascii
        $key_23 = "Windows:" ascii
        $key_24 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}