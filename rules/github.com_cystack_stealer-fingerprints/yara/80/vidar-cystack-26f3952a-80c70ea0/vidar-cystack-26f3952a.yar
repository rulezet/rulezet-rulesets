rule Vidar_cystack_26f3952a
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_26f3952a"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Cataclysm:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "FTL:" ascii
        $key_8 = "Fallout:" ascii
        $key_9 = "GUID:" ascii
        $key_10 = "HWID:" ascii
        $key_11 = "IP:" ascii
        $key_12 = "Install Date:" ascii
        $key_13 = "Keyboard Languages:" ascii
        $key_14 = "Local Time:" ascii
        $key_15 = "MachineID:" ascii
        $key_16 = "Nexomon:" ascii
        $key_17 = "Path:" ascii
        $key_18 = "Plague Inc:" ascii
        $key_19 = "Processor:" ascii
        $key_20 = "RAM:" ascii
        $key_21 = "Rebuild 3:" ascii
        $key_22 = "Telegram:" ascii
        $key_23 = "The Binding of Isaac:" ascii
        $key_24 = "Threads:" ascii
        $key_25 = "TimeZone:" ascii
        $key_26 = "Tower Tactics:" ascii
        $key_27 = "User Name:" ascii
        $key_28 = "Version:" ascii
        $key_29 = "VideoCard:" ascii
        $key_30 = "Windows:" ascii
        $key_31 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}