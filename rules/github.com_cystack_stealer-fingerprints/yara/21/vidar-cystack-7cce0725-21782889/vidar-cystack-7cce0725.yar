rule Vidar_cystack_7cce0725
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_7cce0725"

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
        $key_21 = "Shadowverse:" ascii
        $key_22 = "Threads:" ascii
        $key_23 = "TimeZone:" ascii
        $key_24 = "User Name:" ascii
        $key_25 = "VideoCard:" ascii
        $key_26 = "Windows:" ascii
        $key_27 = "Work Dir:" ascii
        $key_28 = "Zold:" ascii

    condition:
        all of ($key_*)
}