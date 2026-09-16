rule Vidar_cystack_bc53e14f
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_bc53e14f"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Black Myth:" ascii
        $key_2 = "Bureau of Contacts:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Display Resolution:" ascii
        $key_6 = "Install Date:" ascii
        $key_7 = "Keyboard Languages:" ascii
        $key_8 = "Local Time:" ascii
        $key_9 = "Path:" ascii
        $key_10 = "Processor:" ascii
        $key_11 = "RAM:" ascii
        $key_12 = "The Devourer:" ascii
        $key_13 = "Threads:" ascii
        $key_14 = "TimeZone:" ascii
        $key_15 = "User Name:" ascii
        $key_16 = "VideoCard:" ascii
        $key_17 = "Windows:" ascii
        $key_18 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}