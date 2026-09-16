rule Vidar_cystack_3328ff6f
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_3328ff6f"

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
        $key_12 = "Kebab Simulator:" ascii
        $key_13 = "Keyboard Languages:" ascii
        $key_14 = "Local Time:" ascii
        $key_15 = "MachineID:" ascii
        $key_16 = "PUBG:" ascii
        $key_17 = "Path:" ascii
        $key_18 = "Processor:" ascii
        $key_19 = "RAM:" ascii
        $key_20 = "Riot Control Simulator:" ascii
        $key_21 = "Sky:" ascii
        $key_22 = "Sunset Motel:" ascii
        $key_23 = "Threads:" ascii
        $key_24 = "TimeZone:" ascii
        $key_25 = "Tobacco Shop Simulator:" ascii
        $key_26 = "Truck World:" ascii
        $key_27 = "User Name:" ascii
        $key_28 = "Version:" ascii
        $key_29 = "VideoCard:" ascii
        $key_30 = "Windows:" ascii
        $key_31 = "Work Dir:" ascii
        $key_32 = "Wrap House Simulator:" ascii

    condition:
        all of ($key_*)
}