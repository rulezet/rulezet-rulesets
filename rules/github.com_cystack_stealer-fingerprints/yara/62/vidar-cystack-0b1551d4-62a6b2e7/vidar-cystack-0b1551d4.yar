rule Vidar_cystack_0b1551d4
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_0b1551d4"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Academia:" ascii
        $key_2 = "Age of Empires II:" ascii
        $key_3 = "Alien Swarm:" ascii
        $key_4 = "Computer Name:" ascii
        $key_5 = "Cores:" ascii
        $key_6 = "Country:" ascii
        $key_7 = "Date:" ascii
        $key_8 = "Display Resolution:" ascii
        $key_9 = "GUID:" ascii
        $key_10 = "HWID:" ascii
        $key_11 = "Hollow Knight:" ascii
        $key_12 = "Install Date:" ascii
        $key_13 = "Ip:" ascii
        $key_14 = "Keyboard Languages:" ascii
        $key_15 = "Local Time:" ascii
        $key_16 = "MachineID:" ascii
        $key_17 = "PANOPTYCA:" ascii
        $key_18 = "Path:" ascii
        $key_19 = "Processor:" ascii
        $key_20 = "RAM:" ascii
        $key_21 = "Threads:" ascii
        $key_22 = "TimeZone:" ascii
        $key_23 = "User Name:" ascii
        $key_24 = "VideoCard:" ascii
        $key_25 = "Windows:" ascii
        $key_26 = "Work Dir:" ascii
        $key_27 = "World in Conflict:" ascii

    condition:
        all of ($key_*)
}