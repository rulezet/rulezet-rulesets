rule Vidar_cystack_460a4342
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_460a4342"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Asphalt 9:" ascii
        $key_2 = "Battle Realms:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "Grand Theft Auto IV:" ascii
        $key_8 = "Install Date:" ascii
        $key_9 = "KartRider:" ascii
        $key_10 = "Keyboard Languages:" ascii
        $key_11 = "Local Time:" ascii
        $key_12 = "NARUTO SHIPPUDEN:" ascii
        $key_13 = "Processor:" ascii
        $key_14 = "RAM:" ascii
        $key_15 = "Threads:" ascii
        $key_16 = "TimeZone:" ascii
        $key_17 = "User Name:" ascii
        $key_18 = "VideoCard:" ascii
        $key_19 = "Windows:" ascii
        $key_20 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}