rule Vidar_cystack_18b669fa
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_18b669fa"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Blue Protocol:" ascii
        $key_2 = "Car Dealer Simulator:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Date:" ascii
        $key_7 = "Display Resolution:" ascii
        $key_8 = "Install Date:" ascii
        $key_9 = "Ip:" ascii
        $key_10 = "Keyboard Languages:" ascii
        $key_11 = "Local Time:" ascii
        $key_12 = "Processor:" ascii
        $key_13 = "Quarantine Zone:" ascii
        $key_14 = "RAM:" ascii
        $key_15 = "Sonic Racing:" ascii
        $key_16 = "Tainted Grail:" ascii
        $key_17 = "Threads:" ascii
        $key_18 = "TimeZone:" ascii
        $key_19 = "User Name:" ascii
        $key_20 = "VideoCard:" ascii
        $key_21 = "Windows:" ascii
        $key_22 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}