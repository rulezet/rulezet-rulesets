rule Vidar_cystack_6a960711
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_6a960711"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Display Resolution:" ascii
        $key_4 = "Install Date:" ascii
        $key_5 = "Keyboard Languages:" ascii
        $key_6 = "Local Time:" ascii
        $key_7 = "RAM:" ascii
        $key_8 = "Threads:" ascii
        $key_9 = "TimeZone:" ascii
        $key_10 = "User Name:" ascii
        $key_11 = "Windows:" ascii
        $key_12 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}