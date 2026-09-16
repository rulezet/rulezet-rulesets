rule Vidar_cystack_0c43e5bc
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_0c43e5bc"

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
        $key_25 = "Processor:" ascii
        $key_26 = "RAM:" ascii
        $key_27 = "Threads:" ascii
        $key_28 = "TimeZone:" ascii
        $key_29 = "User Name:" ascii
        $key_30 = "Version:" ascii
        $key_31 = "VideoCard:" ascii
        $key_32 = "Windows:" ascii
        $key_33 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}