rule Vidar_cystack_e1155873
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_e1155873"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Ant Colony:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "GUID:" ascii
        $key_8 = "HWID:" ascii
        $key_9 = "IP:" ascii
        $key_10 = "Install Date:" ascii
        $key_11 = "Keyboard Languages:" ascii
        $key_12 = "Local Time:" ascii
        $key_13 = "Lonely Mountains:" ascii
        $key_14 = "MachineID:" ascii
        $key_15 = "Microtopia:" ascii
        $key_16 = "Money Simulator:" ascii
        $key_17 = "Path:" ascii
        $key_18 = "Processor:" ascii
        $key_19 = "RAM:" ascii
        $key_20 = "RISK:" ascii
        $key_21 = "Slapshot:" ascii
        $key_22 = "Telegram:" ascii
        $key_23 = "Threads:" ascii
        $key_24 = "TimeZone:" ascii
        $key_25 = "User Name:" ascii
        $key_26 = "Version:" ascii
        $key_27 = "VideoCard:" ascii
        $key_28 = "Windows:" ascii
        $key_29 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}