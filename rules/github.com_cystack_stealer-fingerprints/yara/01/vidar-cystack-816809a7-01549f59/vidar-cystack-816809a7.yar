rule Vidar_cystack_816809a7
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_816809a7"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Bang-On Balls:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "ENDER LILIES:" ascii
        $key_8 = "Gal Guardians:" ascii
        $key_9 = "Install Date:" ascii
        $key_10 = "Ip:" ascii
        $key_11 = "Keyboard Languages:" ascii
        $key_12 = "Local Time:" ascii
        $key_13 = "Lone Survivor:" ascii
        $key_14 = "Momodora:" ascii
        $key_15 = "NARUTO SHIPPUDEN:" ascii
        $key_16 = "Path:" ascii
        $key_17 = "Processor:" ascii
        $key_18 = "RAM:" ascii
        $key_19 = "Serious Sam 3:" ascii
        $key_20 = "Shovel Knight:" ascii
        $key_21 = "Teenage Mutant Ninja Turtles:" ascii
        $key_22 = "Threads:" ascii
        $key_23 = "TimeZone:" ascii
        $key_24 = "User Name:" ascii
        $key_25 = "VideoCard:" ascii
        $key_26 = "Windows:" ascii
        $key_27 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}