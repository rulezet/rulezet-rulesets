rule Vidar_cystack_46e503a4
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_46e503a4"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Castlevania:" ascii
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
        $key_14 = "Magic:" ascii
        $key_15 = "Path:" ascii
        $key_16 = "Processor:" ascii
        $key_17 = "RAM:" ascii
        $key_18 = "Sucker for Love:" ascii
        $key_19 = "Tainted Grail:" ascii
        $key_20 = "The Walking Dead:" ascii
        $key_21 = "Threads:" ascii
        $key_22 = "TimeZone:" ascii
        $key_23 = "User Name:" ascii
        $key_24 = "VideoCard:" ascii
        $key_25 = "Windows:" ascii
        $key_26 = "Wolfenstein:" ascii
        $key_27 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}