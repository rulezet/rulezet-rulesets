rule Vidar_cystack_6938d00a
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_6938d00a"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Angel Legion:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Dire Destiny:" ascii
        $key_7 = "Display Resolution:" ascii
        $key_8 = "ENDER LILIES:" ascii
        $key_9 = "GUID:" ascii
        $key_10 = "HWID:" ascii
        $key_11 = "Install Date:" ascii
        $key_12 = "Ip:" ascii
        $key_13 = "Keyboard Languages:" ascii
        $key_14 = "Local Time:" ascii
        $key_15 = "MachineID:" ascii
        $key_16 = "Nexomon:" ascii
        $key_17 = "Path:" ascii
        $key_18 = "Processor:" ascii
        $key_19 = "RAM:" ascii
        $key_20 = "Threads:" ascii
        $key_21 = "TimeZone:" ascii
        $key_22 = "User Name:" ascii
        $key_23 = "VideoCard:" ascii
        $key_24 = "Windows:" ascii
        $key_25 = "Work Dir:" ascii
        $key_26 = "Zold:" ascii

    condition:
        all of ($key_*)
}