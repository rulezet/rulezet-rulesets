rule Vidar_cystack_ef23cbd2
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_ef23cbd2"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Battlefield:" ascii
        $key_2 = "Beyond:" ascii
        $key_3 = "Call of Duty:" ascii
        $key_4 = "Call of Duty 4:" ascii
        $key_5 = "Call to Arms - Gates of Hell:" ascii
        $key_6 = "Computer Name:" ascii
        $key_7 = "Cores:" ascii
        $key_8 = "Country:" ascii
        $key_9 = "Date:" ascii
        $key_10 = "Detroit:" ascii
        $key_11 = "Display Resolution:" ascii
        $key_12 = "Draft Day Sports:" ascii
        $key_13 = "Empire:" ascii
        $key_14 = "Feed and Grow:" ascii
        $key_15 = "Football Coach:" ascii
        $key_16 = "GUID:" ascii
        $key_17 = "HWID:" ascii
        $key_18 = "Homefront:" ascii
        $key_19 = "Install Date:" ascii
        $key_20 = "Ip:" ascii
        $key_21 = "Keyboard Languages:" ascii
        $key_22 = "Local Time:" ascii
        $key_23 = "MachineID:" ascii
        $key_24 = "Men of War:" ascii
        $key_25 = "NASCAR 21:" ascii
        $key_26 = "Napoleon:" ascii
        $key_27 = "Path:" ascii
        $key_28 = "Processor:" ascii
        $key_29 = "RAM:" ascii
        $key_30 = "Threads:" ascii
        $key_31 = "TimeZone:" ascii
        $key_32 = "Total Conflict:" ascii
        $key_33 = "Total War:" ascii
        $key_34 = "User Name:" ascii
        $key_35 = "Version:" ascii
        $key_36 = "VideoCard:" ascii
        $key_37 = "Windows:" ascii
        $key_38 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}