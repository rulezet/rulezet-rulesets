rule Vidar_cystack_cbac55ec
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_cbac55ec"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Baccarat Online:" ascii
        $key_2 = "Banker Simulator:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Counter-Strike Nexon:" ascii
        $key_6 = "Country:" ascii
        $key_7 = "Date:" ascii
        $key_8 = "Display Resolution:" ascii
        $key_9 = "GUID:" ascii
        $key_10 = "HWID:" ascii
        $key_11 = "Install Date:" ascii
        $key_12 = "Ip:" ascii
        $key_13 = "Kebab Simulator:" ascii
        $key_14 = "Keyboard Languages:" ascii
        $key_15 = "Local Time:" ascii
        $key_16 = "MachineID:" ascii
        $key_17 = "Mall Simulator:" ascii
        $key_18 = "Only Up:" ascii
        $key_19 = "PUBG:" ascii
        $key_20 = "Path:" ascii
        $key_21 = "Processor:" ascii
        $key_22 = "RAM:" ascii
        $key_23 = "Supermarket Simulator:" ascii
        $key_24 = "Threads:" ascii
        $key_25 = "TimeZone:" ascii
        $key_26 = "User Name:" ascii
        $key_27 = "VideoCard:" ascii
        $key_28 = "Windows:" ascii
        $key_29 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}