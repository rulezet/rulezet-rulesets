rule Vidar_cystack_13786e78
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_13786e78"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Date:" ascii
        $key_5 = "Display Resolution:" ascii
        $key_6 = "Install Date:" ascii
        $key_7 = "Ip:" ascii
        $key_8 = "Keyboard Languages:" ascii
        $key_9 = "Local Time:" ascii
        $key_10 = "Only Up:" ascii
        $key_11 = "Path:" ascii
        $key_12 = "Prison Escape Simulator:" ascii
        $key_13 = "Processor:" ascii
        $key_14 = "RAM:" ascii
        $key_15 = "SCP:" ascii
        $key_16 = "Sleeping Dogs:" ascii
        $key_17 = "Stick Fight:" ascii
        $key_18 = "Threads:" ascii
        $key_19 = "TimeZone:" ascii
        $key_20 = "User Name:" ascii
        $key_21 = "VideoCard:" ascii
        $key_22 = "Windows:" ascii
        $key_23 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}