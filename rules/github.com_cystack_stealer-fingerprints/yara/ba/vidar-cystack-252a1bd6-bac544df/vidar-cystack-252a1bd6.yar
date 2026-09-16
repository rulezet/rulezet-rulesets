rule Vidar_cystack_252a1bd6
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_252a1bd6"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Date:" ascii
        $key_5 = "Display Resolution:" ascii
        $key_6 = "Enderal:" ascii
        $key_7 = "Fallout 4:" ascii
        $key_8 = "GUID:" ascii
        $key_9 = "Ghost Girl Ghussy:" ascii
        $key_10 = "HWID:" ascii
        $key_11 = "Install Date:" ascii
        $key_12 = "Ip:" ascii
        $key_13 = "Keyboard Languages:" ascii
        $key_14 = "Local Time:" ascii
        $key_15 = "MachineID:" ascii
        $key_16 = "NieR:" ascii
        $key_17 = "PANOPTYCA:" ascii
        $key_18 = "Path:" ascii
        $key_19 = "Processor:" ascii
        $key_20 = "RAM:" ascii
        $key_21 = "Skyrim Special Edition:" ascii
        $key_22 = "Threads:" ascii
        $key_23 = "TimeZone:" ascii
        $key_24 = "Total War:" ascii
        $key_25 = "Umamusume:" ascii
        $key_26 = "User Name:" ascii
        $key_27 = "VideoCard:" ascii
        $key_28 = "Windows:" ascii
        $key_29 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}