rule Vidar_cystack_940317a8
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_940317a8"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Date:" ascii
        $key_5 = "Display Resolution:" ascii
        $key_6 = "GUID:" ascii
        $key_7 = "Ghostbane:" ascii
        $key_8 = "HWID:" ascii
        $key_9 = "In Sink:" ascii
        $key_10 = "Install Date:" ascii
        $key_11 = "Ip:" ascii
        $key_12 = "Jelly Brawl:" ascii
        $key_13 = "Keyboard Languages:" ascii
        $key_14 = "Local Time:" ascii
        $key_15 = "MachineID:" ascii
        $key_16 = "Path:" ascii
        $key_17 = "Processor:" ascii
        $key_18 = "RAM:" ascii
        $key_19 = "Schedule I:" ascii
        $key_20 = "Scheming Through The Zombie Apocalypse:" ascii
        $key_21 = "Sky:" ascii
        $key_22 = "Threads:" ascii
        $key_23 = "TimeZone:" ascii
        $key_24 = "Tobacco Shop Simulator:" ascii
        $key_25 = "User Name:" ascii
        $key_26 = "VideoCard:" ascii
        $key_27 = "WWR:" ascii
        $key_28 = "Windows:" ascii
        $key_29 = "Work Dir:" ascii
        $key_30 = "World Crafter TD:" ascii

    condition:
        all of ($key_*)
}