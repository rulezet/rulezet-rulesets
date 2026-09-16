rule Vidar_cystack_349c596d
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_349c596d"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Casino Island Simulator:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Cowboy Life Simulator:" ascii
        $key_6 = "Date:" ascii
        $key_7 = "Display Resolution:" ascii
        $key_8 = "Drive Thru Simulator:" ascii
        $key_9 = "GUID:" ascii
        $key_10 = "Gym Manager:" ascii
        $key_11 = "HWID:" ascii
        $key_12 = "Install Date:" ascii
        $key_13 = "Ip:" ascii
        $key_14 = "KIBORG:" ascii
        $key_15 = "Keyboard Languages:" ascii
        $key_16 = "Local Time:" ascii
        $key_17 = "MachineID:" ascii
        $key_18 = "Path:" ascii
        $key_19 = "Processor:" ascii
        $key_20 = "RAM:" ascii
        $key_21 = "Riot Control Simulator:" ascii
        $key_22 = "SWAT Commander:" ascii
        $key_23 = "Sunset Motel:" ascii
        $key_24 = "Threads:" ascii
        $key_25 = "TimeZone:" ascii
        $key_26 = "User Name:" ascii
        $key_27 = "VideoCard:" ascii
        $key_28 = "Windows:" ascii
        $key_29 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}