rule Vidar_cystack_64d58f3b
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_64d58f3b"

    strings:
        $key_0 = "ARK:" ascii
        $key_1 = "AV:" ascii
        $key_2 = "Arena Breakout:" ascii
        $key_3 = "Cities:" ascii
        $key_4 = "Computer Name:" ascii
        $key_5 = "Cores:" ascii
        $key_6 = "Country:" ascii
        $key_7 = "Date:" ascii
        $key_8 = "Display Resolution:" ascii
        $key_9 = "GUID:" ascii
        $key_10 = "HWID:" ascii
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