rule Vidar_cystack_69b616ad
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_69b616ad"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Backrooms:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "Entropy:" ascii
        $key_8 = "Half-Life:" ascii
        $key_9 = "Half-Life 2:" ascii
        $key_10 = "IP:" ascii
        $key_11 = "Install Date:" ascii
        $key_12 = "Keyboard Languages:" ascii
        $key_13 = "Local Time:" ascii
        $key_14 = "Path:" ascii
        $key_15 = "Processor:" ascii
        $key_16 = "RAM:" ascii
        $key_17 = "SCP:" ascii
        $key_18 = "Threads:" ascii
        $key_19 = "TimeZone:" ascii
        $key_20 = "User Name:" ascii
        $key_21 = "Version:" ascii
        $key_22 = "VideoCard:" ascii
        $key_23 = "Windows:" ascii
        $key_24 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}