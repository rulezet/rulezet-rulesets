rule Vidar_cystack_665eba8a
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_665eba8a"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Blue Protocol:" ascii
        $key_2 = "Car Dealer Simulator:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "Install Date:" ascii
        $key_8 = "Keyboard Languages:" ascii
        $key_9 = "Local Time:" ascii
        $key_10 = "Processor:" ascii
        $key_11 = "Quarantine Zone:" ascii
        $key_12 = "RAM:" ascii
        $key_13 = "Sonic Racing:" ascii
        $key_14 = "Tainted Grail:" ascii
        $key_15 = "Threads:" ascii
        $key_16 = "TimeZone:" ascii
        $key_17 = "User Name:" ascii
        $key_18 = "VideoCard:" ascii
        $key_19 = "Windows:" ascii
        $key_20 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}