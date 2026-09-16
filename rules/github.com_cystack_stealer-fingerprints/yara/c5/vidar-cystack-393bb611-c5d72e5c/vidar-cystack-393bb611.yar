rule Vidar_cystack_393bb611
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_393bb611"

    strings:
        $key_0 = "A Plague Tale:" ascii
        $key_1 = "AV:" ascii
        $key_2 = "Banishers:" ascii
        $key_3 = "Batman:" ascii
        $key_4 = "Beyond:" ascii
        $key_5 = "Clair Obscur:" ascii
        $key_6 = "Computer Name:" ascii
        $key_7 = "Cores:" ascii
        $key_8 = "Country:" ascii
        $key_9 = "Date:" ascii
        $key_10 = "Detroit:" ascii
        $key_11 = "Display Resolution:" ascii
        $key_12 = "GUID:" ascii
        $key_13 = "God of War:" ascii
        $key_14 = "HWID:" ascii
        $key_15 = "Install Date:" ascii
        $key_16 = "Ip:" ascii
        $key_17 = "Kena:" ascii
        $key_18 = "Keyboard Languages:" ascii
        $key_19 = "Life is Strange:" ascii
        $key_20 = "Local Time:" ascii
        $key_21 = "MachineID:" ascii
        $key_22 = "NieR:" ascii
        $key_23 = "Nioh 2:" ascii
        $key_24 = "Path:" ascii
        $key_25 = "Prince of Persia:" ascii
        $key_26 = "Processor:" ascii
        $key_27 = "RAM:" ascii
        $key_28 = "Resident Evil:" ascii
        $key_29 = "Threads:" ascii
        $key_30 = "TimeZone:" ascii
        $key_31 = "User Name:" ascii
        $key_32 = "Version:" ascii
        $key_33 = "VideoCard:" ascii
        $key_34 = "Windows:" ascii
        $key_35 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}