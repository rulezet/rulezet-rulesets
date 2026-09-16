rule Vidar_cystack_b7445647
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_b7445647"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Coloring Game:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "CryptoClickers:" ascii
        $key_6 = "Dark Fantasy:" ascii
        $key_7 = "Dark Fantasy 2:" ascii
        $key_8 = "Date:" ascii
        $key_9 = "Display Resolution:" ascii
        $key_10 = "GUID:" ascii
        $key_11 = "HWID:" ascii
        $key_12 = "Install Date:" ascii
        $key_13 = "Ip:" ascii
        $key_14 = "Jigsaw Puzzle:" ascii
        $key_15 = "Keyboard Languages:" ascii
        $key_16 = "Local Time:" ascii
        $key_17 = "MachineID:" ascii
        $key_18 = "Path:" ascii
        $key_19 = "Processor:" ascii
        $key_20 = "RAM:" ascii
        $key_21 = "STAR WARS Jedi:" ascii
        $key_22 = "Tainted Grail:" ascii
        $key_23 = "Threads:" ascii
        $key_24 = "TimeZone:" ascii
        $key_25 = "User Name:" ascii
        $key_26 = "VideoCard:" ascii
        $key_27 = "Windows:" ascii
        $key_28 = "Work Dir:" ascii
        $key_29 = "World of Talesworth:" ascii

    condition:
        all of ($key_*)
}