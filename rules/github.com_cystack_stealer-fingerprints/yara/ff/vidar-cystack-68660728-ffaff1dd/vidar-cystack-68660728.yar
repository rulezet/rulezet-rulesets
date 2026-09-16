rule Vidar_cystack_68660728
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_68660728"

    strings:
        $key_0 = "ARK:" ascii
        $key_1 = "AV:" ascii
        $key_2 = "Alien Breed:" ascii
        $key_3 = "Alien Breed 2:" ascii
        $key_4 = "Alien Breed 3:" ascii
        $key_5 = "Aliens:" ascii
        $key_6 = "Computer Name:" ascii
        $key_7 = "Cores:" ascii
        $key_8 = "Country:" ascii
        $key_9 = "Date:" ascii
        $key_10 = "Detroit:" ascii
        $key_11 = "Disciples:" ascii
        $key_12 = "Display Resolution:" ascii
        $key_13 = "Giana Sisters:" ascii
        $key_14 = "Homeworld:" ascii
        $key_15 = "Install Date:" ascii
        $key_16 = "Ip:" ascii
        $key_17 = "Keyboard Languages:" ascii
        $key_18 = "Kingdoms of Amalur:" ascii
        $key_19 = "Local Time:" ascii
        $key_20 = "Path:" ascii
        $key_21 = "Pathfinder:" ascii
        $key_22 = "Processor:" ascii
        $key_23 = "RAM:" ascii
        $key_24 = "STAR WARS Jedi:" ascii
        $key_25 = "TRANSFORMERS:" ascii
        $key_26 = "The Witcher 3:" ascii
        $key_27 = "Threads:" ascii
        $key_28 = "TimeZone:" ascii
        $key_29 = "Total War:" ascii
        $key_30 = "User Name:" ascii
        $key_31 = "VideoCard:" ascii
        $key_32 = "Windows:" ascii
        $key_33 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}