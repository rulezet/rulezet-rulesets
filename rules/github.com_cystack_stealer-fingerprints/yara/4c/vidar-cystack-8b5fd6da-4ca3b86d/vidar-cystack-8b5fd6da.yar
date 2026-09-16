rule Vidar_cystack_8b5fd6da
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_8b5fd6da"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Cores:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Date:" ascii
        $key_4 = "Display Resolution:" ascii
        $key_5 = "GUID:" ascii
        $key_6 = "HWID:" ascii
        $key_7 = "Install Date:" ascii
        $key_8 = "Ip:" ascii
        $key_9 = "Jotunnslayer:" ascii
        $key_10 = "Keyboard Languages:" ascii
        $key_11 = "Local Time:" ascii
        $key_12 = "MachineID:" ascii
        $key_13 = "Path:" ascii
        $key_14 = "Processor:" ascii
        $key_15 = "RAM:" ascii
        $key_16 = "Threads:" ascii
        $key_17 = "TimeZone:" ascii
        $key_18 = "User Name:" ascii
        $key_19 = "VideoCard:" ascii
        $key_20 = "Windows:" ascii
        $key_21 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}