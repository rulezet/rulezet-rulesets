rule Vidar_cystack_72ad094c
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_72ad094c"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Bro Falls:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Contraband Police:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Crime Simulator:" ascii
        $key_7 = "Date:" ascii
        $key_8 = "Display Resolution:" ascii
        $key_9 = "Escape Memoirs:" ascii
        $key_10 = "GUID:" ascii
        $key_11 = "HWID:" ascii
        $key_12 = "Hello Guest:" ascii
        $key_13 = "In Sink:" ascii
        $key_14 = "Install Date:" ascii
        $key_15 = "Ip:" ascii
        $key_16 = "Kebab Simulator:" ascii
        $key_17 = "Keyboard Languages:" ascii
        $key_18 = "Local Time:" ascii
        $key_19 = "MachineID:" ascii
        $key_20 = "Ocean World:" ascii
        $key_21 = "Path:" ascii
        $key_22 = "Pixel Gun 3D:" ascii
        $key_23 = "Processor:" ascii
        $key_24 = "RAM:" ascii
        $key_25 = "SCP:" ascii
        $key_26 = "Slapshot:" ascii
        $key_27 = "Supermarket Simulator:" ascii
        $key_28 = "Threads:" ascii
        $key_29 = "TimeZone:" ascii
        $key_30 = "User Name:" ascii
        $key_31 = "VideoCard:" ascii
        $key_32 = "Windows:" ascii
        $key_33 = "Work Dir:" ascii
        $key_34 = "World of Guns:" ascii

    condition:
        all of ($key_*)
}