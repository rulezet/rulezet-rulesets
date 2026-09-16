rule Vidar_cystack_750ef9ad
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_750ef9ad"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Age of Empires II:" ascii
        $key_2 = "Age of Empires IV:" ascii
        $key_3 = "Aliens:" ascii
        $key_4 = "Backrooms:" ascii
        $key_5 = "Call to Arms - Gates of Hell:" ascii
        $key_6 = "Computer Name:" ascii
        $key_7 = "Cores:" ascii
        $key_8 = "Country:" ascii
        $key_9 = "Date:" ascii
        $key_10 = "Display Resolution:" ascii
        $key_11 = "Install Date:" ascii
        $key_12 = "Ip:" ascii
        $key_13 = "Keyboard Languages:" ascii
        $key_14 = "Local Time:" ascii
        $key_15 = "Processor:" ascii
        $key_16 = "RAM:" ascii
        $key_17 = "The Elder Scrolls IV:" ascii
        $key_18 = "Threads:" ascii
        $key_19 = "TimeZone:" ascii
        $key_20 = "User Name:" ascii
        $key_21 = "VideoCard:" ascii
        $key_22 = "Windows:" ascii
        $key_23 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}