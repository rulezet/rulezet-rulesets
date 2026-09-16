rule Vidar_cystack_cde14c38
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_cde14c38"

    strings:
        $key_0 = "ARK:" ascii
        $key_1 = "AV:" ascii
        $key_2 = "Ancestors:" ascii
        $key_3 = "Ben 10:" ascii
        $key_4 = "Computer Name:" ascii
        $key_5 = "Cores:" ascii
        $key_6 = "Country:" ascii
        $key_7 = "DRAGON BALL:" ascii
        $key_8 = "Date:" ascii
        $key_9 = "Display Resolution:" ascii
        $key_10 = "Far Cry:" ascii
        $key_11 = "GUID:" ascii
        $key_12 = "God of War:" ascii
        $key_13 = "HWID:" ascii
        $key_14 = "Install Date:" ascii
        $key_15 = "Ip:" ascii
        $key_16 = "Keyboard Languages:" ascii
        $key_17 = "Local Time:" ascii
        $key_18 = "MachineID:" ascii
        $key_19 = "Path:" ascii
        $key_20 = "Processor:" ascii
        $key_21 = "RAM:" ascii
        $key_22 = "Spider-Man:" ascii
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