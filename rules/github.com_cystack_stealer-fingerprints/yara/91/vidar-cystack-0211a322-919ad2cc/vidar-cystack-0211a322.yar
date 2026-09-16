rule Vidar_cystack_0211a322
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_0211a322"

    strings:
        $key_0 = "A Plague Tale:" ascii
        $key_1 = "AV:" ascii
        $key_2 = "Clair Obscur:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Date:" ascii
        $key_7 = "Disgaea 7:" ascii
        $key_8 = "Display Resolution:" ascii
        $key_9 = "Dying Light:" ascii
        $key_10 = "Dying Light 2:" ascii
        $key_11 = "GUID:" ascii
        $key_12 = "HWID:" ascii
        $key_13 = "Install Date:" ascii
        $key_14 = "Ip:" ascii
        $key_15 = "Keyboard Languages:" ascii
        $key_16 = "Local Time:" ascii
        $key_17 = "MachineID:" ascii
        $key_18 = "Mafia:" ascii
        $key_19 = "NARAKA:" ascii
        $key_20 = "PUBG:" ascii
        $key_21 = "Path:" ascii
        $key_22 = "Police Simulator:" ascii
        $key_23 = "Processor:" ascii
        $key_24 = "RAM:" ascii
        $key_25 = "The First Berserker:" ascii
        $key_26 = "Threads:" ascii
        $key_27 = "TimeZone:" ascii
        $key_28 = "User Name:" ascii
        $key_29 = "Version:" ascii
        $key_30 = "VideoCard:" ascii
        $key_31 = "Windows:" ascii
        $key_32 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}