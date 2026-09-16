rule Vidar_cystack_0ccb112f
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_0ccb112f"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Car Dealer Simulator:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Deconstruction Simulator:" ascii
        $key_7 = "Display Resolution:" ascii
        $key_8 = "GUID:" ascii
        $key_9 = "Gamer Stop Simulator:" ascii
        $key_10 = "HWID:" ascii
        $key_11 = "Install Date:" ascii
        $key_12 = "Ip:" ascii
        $key_13 = "Kebab Simulator:" ascii
        $key_14 = "Keyboard Languages:" ascii
        $key_15 = "Local Time:" ascii
        $key_16 = "MachineID:" ascii
        $key_17 = "PUBG:" ascii
        $key_18 = "Path:" ascii
        $key_19 = "Processor:" ascii
        $key_20 = "RAM:" ascii
        $key_21 = "Riot Control Simulator:" ascii
        $key_22 = "Sky:" ascii
        $key_23 = "Sunset Motel:" ascii
        $key_24 = "Threads:" ascii
        $key_25 = "TimeZone:" ascii
        $key_26 = "Tobacco Shop Simulator:" ascii
        $key_27 = "Truck World:" ascii
        $key_28 = "User Name:" ascii
        $key_29 = "Version:" ascii
        $key_30 = "VideoCard:" ascii
        $key_31 = "Windows:" ascii
        $key_32 = "Work Dir:" ascii
        $key_33 = "Wrap House Simulator:" ascii

    condition:
        all of ($key_*)
}