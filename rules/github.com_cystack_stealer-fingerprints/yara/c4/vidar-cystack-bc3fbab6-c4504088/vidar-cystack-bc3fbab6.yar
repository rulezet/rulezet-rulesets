rule Vidar_cystack_bc3fbab6
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_bc3fbab6"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Alien Swarm:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Display Resolution:" ascii
        $key_6 = "Fallout:" ascii
        $key_7 = "Install Date:" ascii
        $key_8 = "Ip:" ascii
        $key_9 = "Keyboard Languages:" ascii
        $key_10 = "Local Time:" ascii
        $key_11 = "Monster Hunter:" ascii
        $key_12 = "Processor:" ascii
        $key_13 = "RAM:" ascii
        $key_14 = "Threads:" ascii
        $key_15 = "TimeZone:" ascii
        $key_16 = "User Name:" ascii
        $key_17 = "VideoCard:" ascii
        $key_18 = "Windows:" ascii
        $key_19 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}