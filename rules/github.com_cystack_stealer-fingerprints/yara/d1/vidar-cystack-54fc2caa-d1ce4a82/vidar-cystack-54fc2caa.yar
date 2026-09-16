rule Vidar_cystack_54fc2caa
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_54fc2caa"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Age of Empires:" ascii
        $key_2 = "Age of Mythology:" ascii
        $key_3 = "Castlevania:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Date:" ascii
        $key_7 = "Display Resolution:" ascii
        $key_8 = "Fallout:" ascii
        $key_9 = "GWENT:" ascii
        $key_10 = "Grand Theft Auto IV:" ascii
        $key_11 = "Install Date:" ascii
        $key_12 = "Ip:" ascii
        $key_13 = "Keyboard Languages:" ascii
        $key_14 = "Local Time:" ascii
        $key_15 = "Processor:" ascii
        $key_16 = "RAM:" ascii
        $key_17 = "Threads:" ascii
        $key_18 = "TimeZone:" ascii
        $key_19 = "User Name:" ascii
        $key_20 = "VideoCard:" ascii
        $key_21 = "Windows:" ascii
        $key_22 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}