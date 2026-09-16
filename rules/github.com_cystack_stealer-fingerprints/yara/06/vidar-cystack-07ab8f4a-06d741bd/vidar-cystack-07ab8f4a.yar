rule Vidar_cystack_07ab8f4a
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_07ab8f4a"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Arena Breakout:" ascii
        $key_2 = "Call of Duty:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Date:" ascii
        $key_7 = "Display Resolution:" ascii
        $key_8 = "GUID:" ascii
        $key_9 = "HWID:" ascii
        $key_10 = "Install Date:" ascii
        $key_11 = "Keyboard Languages:" ascii
        $key_12 = "Local Time:" ascii
        $key_13 = "MachineID:" ascii
        $key_14 = "Path:" ascii
        $key_15 = "Processor:" ascii
        $key_16 = "RAM:" ascii
        $key_17 = "Threads:" ascii
        $key_18 = "TimeZone:" ascii
        $key_19 = "User Name:" ascii
        $key_20 = "VideoCard:" ascii
        $key_21 = "Windows:" ascii
        $key_22 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}