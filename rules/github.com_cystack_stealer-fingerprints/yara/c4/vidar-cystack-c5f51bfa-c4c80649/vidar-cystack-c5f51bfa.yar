rule Vidar_cystack_c5f51bfa
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_c5f51bfa"

    strings:
        $key_0 = "A Total War Saga:" ascii
        $key_1 = "AV:" ascii
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
        $key_12 = "Kingdom Come:" ascii
        $key_13 = "Local Time:" ascii
        $key_14 = "MachineID:" ascii
        $key_15 = "ONE PIECE:" ascii
        $key_16 = "Path:" ascii
        $key_17 = "Processor:" ascii
        $key_18 = "RAM:" ascii
        $key_19 = "Rome:" ascii
        $key_20 = "Stronghold:" ascii
        $key_21 = "Stronghold Crusader:" ascii
        $key_22 = "Threads:" ascii
        $key_23 = "TimeZone:" ascii
        $key_24 = "Total War:" ascii
        $key_25 = "User Name:" ascii
        $key_26 = "VideoCard:" ascii
        $key_27 = "Windows:" ascii
        $key_28 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}