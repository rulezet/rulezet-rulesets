rule Vidar_cystack_d20a2e62
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_d20a2e62"

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
        $key_13 = "Ip:" ascii
        $key_14 = "Keyboard Languages:" ascii
        $key_15 = "Local Time:" ascii
        $key_16 = "MachineID:" ascii
        $key_17 = "Nexomon:" ascii
        $key_18 = "Path:" ascii
        $key_19 = "Processor:" ascii
        $key_20 = "RAM:" ascii
        $key_21 = "Reverse:" ascii
        $key_22 = "Shadowverse:" ascii
        $key_23 = "Species:" ascii
        $key_24 = "The Walking Dead:" ascii
        $key_25 = "Threads:" ascii
        $key_26 = "TimeZone:" ascii
        $key_27 = "User Name:" ascii
        $key_28 = "VideoCard:" ascii
        $key_29 = "Windows:" ascii
        $key_30 = "Work Dir:" ascii
        $key_31 = "Zold:" ascii

    condition:
        all of ($key_*)
}