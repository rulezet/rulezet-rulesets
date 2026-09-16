rule Vidar_cystack_d24389e5
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_d24389e5"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Bully:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Denos City:" ascii
        $key_7 = "Display Resolution:" ascii
        $key_8 = "Glowing Stones:" ascii
        $key_9 = "Install Date:" ascii
        $key_10 = "Ip:" ascii
        $key_11 = "Isabella:" ascii
        $key_12 = "Keyboard Languages:" ascii
        $key_13 = "Living with temptation:" ascii
        $key_14 = "Local Time:" ascii
        $key_15 = "LustyVerse:" ascii
        $key_16 = "Mafia:" ascii
        $key_17 = "Pledge:" ascii
        $key_18 = "Processor:" ascii
        $key_19 = "Projekt:" ascii
        $key_20 = "RAM:" ascii
        $key_21 = "STEPMOM:" ascii
        $key_22 = "Serena:" ascii
        $key_23 = "Threads:" ascii
        $key_24 = "TimeZone:" ascii
        $key_25 = "User Name:" ascii
        $key_26 = "VideoCard:" ascii
        $key_27 = "Windows:" ascii
        $key_28 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}