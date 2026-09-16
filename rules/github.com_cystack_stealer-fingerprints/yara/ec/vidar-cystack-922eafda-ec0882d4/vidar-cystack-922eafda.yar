rule Vidar_cystack_922eafda
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_922eafda"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Ages of Conflict:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "Expeditions:" ascii
        $key_8 = "Feed and Grow:" ascii
        $key_9 = "GUID:" ascii
        $key_10 = "Grand Tactician:" ascii
        $key_11 = "HWID:" ascii
        $key_12 = "IL-2 Sturmovik:" ascii
        $key_13 = "Install Date:" ascii
        $key_14 = "Interstellar Space:" ascii
        $key_15 = "Ip:" ascii
        $key_16 = "Keyboard Languages:" ascii
        $key_17 = "Local Time:" ascii
        $key_18 = "MachineID:" ascii
        $key_19 = "Path:" ascii
        $key_20 = "Plague Inc:" ascii
        $key_21 = "Processor:" ascii
        $key_22 = "RAM:" ascii
        $key_23 = "Star Control:" ascii
        $key_24 = "Stellaris:" ascii
        $key_25 = "Threads:" ascii
        $key_26 = "TimeZone:" ascii
        $key_27 = "Total War:" ascii
        $key_28 = "User Name:" ascii
        $key_29 = "VideoCard:" ascii
        $key_30 = "Windows:" ascii
        $key_31 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}