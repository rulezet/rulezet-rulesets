rule Vidar_cystack_38b41738
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_38b41738"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Age of Empires III:" ascii
        $key_2 = "Command and Conquer:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Cultivation Story:" ascii
        $key_6 = "Digimon Story Cyber Sleuth:" ascii
        $key_7 = "Digimon World:" ascii
        $key_8 = "Display Resolution:" ascii
        $key_9 = "Install Date:" ascii
        $key_10 = "Keyboard Languages:" ascii
        $key_11 = "Local Time:" ascii
        $key_12 = "Monster Hunter:" ascii
        $key_13 = "NARAKA:" ascii
        $key_14 = "Processor:" ascii
        $key_15 = "RAM:" ascii
        $key_16 = "Sleeping Dogs:" ascii
        $key_17 = "Threads:" ascii
        $key_18 = "TimeZone:" ascii
        $key_19 = "User Name:" ascii
        $key_20 = "VideoCard:" ascii
        $key_21 = "Windows:" ascii
        $key_22 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}