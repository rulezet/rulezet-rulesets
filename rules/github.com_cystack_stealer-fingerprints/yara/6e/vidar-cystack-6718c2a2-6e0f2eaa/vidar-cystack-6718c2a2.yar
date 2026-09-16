rule Vidar_cystack_6718c2a2
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_6718c2a2"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Angel Legion:" ascii
        $key_2 = "Atelier Resleriana:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Date:" ascii
        $key_7 = "Dire Destiny:" ascii
        $key_8 = "Display Resolution:" ascii
        $key_9 = "ENDER LILIES:" ascii
        $key_10 = "GUID:" ascii
        $key_11 = "HWID:" ascii
        $key_12 = "Install Date:" ascii
        $key_13 = "Into the Dead:" ascii
        $key_14 = "Ip:" ascii
        $key_15 = "Keyboard Languages:" ascii
        $key_16 = "Local Time:" ascii
        $key_17 = "MachineID:" ascii
        $key_18 = "Nexomon:" ascii
        $key_19 = "Path:" ascii
        $key_20 = "Processor:" ascii
        $key_21 = "RAM:" ascii
        $key_22 = "Reverse:" ascii
        $key_23 = "Shadowverse:" ascii
        $key_24 = "Species:" ascii
        $key_25 = "The Walking Dead:" ascii
        $key_26 = "Threads:" ascii
        $key_27 = "TimeZone:" ascii
        $key_28 = "User Name:" ascii
        $key_29 = "VideoCard:" ascii
        $key_30 = "Windows:" ascii
        $key_31 = "Work Dir:" ascii
        $key_32 = "Zold:" ascii

    condition:
        all of ($key_*)
}