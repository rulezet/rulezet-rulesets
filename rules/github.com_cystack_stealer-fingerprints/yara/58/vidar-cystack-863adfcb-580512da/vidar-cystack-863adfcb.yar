rule Vidar_cystack_863adfcb
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_863adfcb"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Batman:" ascii
        $key_2 = "Beyond:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Counter-Strike:" ascii
        $key_6 = "Dark Hours:" ascii
        $key_7 = "Display Resolution:" ascii
        $key_8 = "Install Date:" ascii
        $key_9 = "Keyboard Languages:" ascii
        $key_10 = "Local Time:" ascii
        $key_11 = "NARUTO SHIPPUDEN:" ascii
        $key_12 = "Processor:" ascii
        $key_13 = "RAM:" ascii
        $key_14 = "Threads:" ascii
        $key_15 = "TimeZone:" ascii
        $key_16 = "User Name:" ascii
        $key_17 = "VideoCard:" ascii

    condition:
        all of ($key_*)
}