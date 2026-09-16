rule Vidar_cystack_bdf29532
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_bdf29532"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Alice:" ascii
        $key_2 = "Beyond:" ascii
        $key_3 = "Bully:" ascii
        $key_4 = "Call of Duty:" ascii
        $key_5 = "Computer Name:" ascii
        $key_6 = "Cores:" ascii
        $key_7 = "Country:" ascii
        $key_8 = "Danganronpa:" ascii
        $key_9 = "Date:" ascii
        $key_10 = "Display Resolution:" ascii
        $key_11 = "GUID:" ascii
        $key_12 = "Grand Theft Auto IV:" ascii
        $key_13 = "HWID:" ascii
        $key_14 = "Injustice:" ascii
        $key_15 = "Install Date:" ascii
        $key_16 = "Ip:" ascii
        $key_17 = "Keyboard Languages:" ascii
        $key_18 = "Local Time:" ascii
        $key_19 = "MachineID:" ascii
        $key_20 = "Path:" ascii
        $key_21 = "Processor:" ascii
        $key_22 = "RAM:" ascii
        $key_23 = "STAR WARS Jedi:" ascii
        $key_24 = "Silent Hill:" ascii
        $key_25 = "The Walking Dead:" ascii
        $key_26 = "The Witcher:" ascii
        $key_27 = "Threads:" ascii
        $key_28 = "TimeZone:" ascii
        $key_29 = "User Name:" ascii
        $key_30 = "VideoCard:" ascii
        $key_31 = "Windows:" ascii
        $key_32 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}