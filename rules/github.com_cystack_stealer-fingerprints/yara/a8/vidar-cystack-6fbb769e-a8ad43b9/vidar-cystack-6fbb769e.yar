rule Vidar_cystack_6fbb769e
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_6fbb769e"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Date:" ascii
        $key_5 = "Detroit:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "IP:" ascii
        $key_8 = "Install Date:" ascii
        $key_9 = "Keyboard Languages:" ascii
        $key_10 = "Local Time:" ascii
        $key_11 = "Mafia II:" ascii
        $key_12 = "Path:" ascii
        $key_13 = "Processor:" ascii
        $key_14 = "RAM:" ascii
        $key_15 = "Sleeping Dogs:" ascii
        $key_16 = "The Elder Scrolls IV:" ascii
        $key_17 = "The Elder Scrolls V:" ascii
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