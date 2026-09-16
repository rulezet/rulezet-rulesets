rule Vidar_cystack_de46706e
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_de46706e"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Date:" ascii
        $key_5 = "Display Resolution:" ascii
        $key_6 = "GUID:" ascii
        $key_7 = "HWID:" ascii
        $key_8 = "Half-Life 2:" ascii
        $key_9 = "Half-Life Deathmatch:" ascii
        $key_10 = "Install Date:" ascii
        $key_11 = "Ip:" ascii
        $key_12 = "Keyboard Languages:" ascii
        $key_13 = "Local Time:" ascii
        $key_14 = "MachineID:" ascii
        $key_15 = "Ocean World:" ascii
        $key_16 = "Path:" ascii
        $key_17 = "Potion Craft:" ascii
        $key_18 = "Processor:" ascii
        $key_19 = "RAM:" ascii
        $key_20 = "RollerCoaster Tycoon 2:" ascii
        $key_21 = "The Binding of Isaac:" ascii
        $key_22 = "Threads:" ascii
        $key_23 = "TimeZone:" ascii
        $key_24 = "User Name:" ascii
        $key_25 = "VideoCard:" ascii
        $key_26 = "Windows:" ascii
        $key_27 = "Work Dir:" ascii
        $key_28 = "Yakuza:" ascii

    condition:
        all of ($key_*)
}