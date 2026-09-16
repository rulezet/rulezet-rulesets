rule Vidar_cystack_6d37b386
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_6d37b386"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Clair Obscur:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "Install Date:" ascii
        $key_8 = "Ip:" ascii
        $key_9 = "Keyboard Languages:" ascii
        $key_10 = "Kingdom Come:" ascii
        $key_11 = "Local Time:" ascii
        $key_12 = "Path:" ascii
        $key_13 = "Processor:" ascii
        $key_14 = "RAM:" ascii
        $key_15 = "STAR WARS Jedi:" ascii
        $key_16 = "Skyrim Special Edition:" ascii
        $key_17 = "The Elder Scrolls IV:" ascii
        $key_18 = "The Elder Scrolls V:" ascii
        $key_19 = "The Witcher 3:" ascii
        $key_20 = "Threads:" ascii
        $key_21 = "TimeZone:" ascii
        $key_22 = "User Name:" ascii
        $key_23 = "VideoCard:" ascii
        $key_24 = "Windows:" ascii
        $key_25 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}