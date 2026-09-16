rule Vidar_cystack_8345abd9
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_8345abd9"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Batman:" ascii
        $key_2 = "Call of Duty:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Date:" ascii
        $key_7 = "Display Resolution:" ascii
        $key_8 = "Dying Light:" ascii
        $key_9 = "GUID:" ascii
        $key_10 = "HWID:" ascii
        $key_11 = "Hitman:" ascii
        $key_12 = "Hitman 2:" ascii
        $key_13 = "Install Date:" ascii
        $key_14 = "Ip:" ascii
        $key_15 = "Keyboard Languages:" ascii
        $key_16 = "Local Time:" ascii
        $key_17 = "MachineID:" ascii
        $key_18 = "PUBG:" ascii
        $key_19 = "Path:" ascii
        $key_20 = "Police Simulator:" ascii
        $key_21 = "Processor:" ascii
        $key_22 = "RAM:" ascii
        $key_23 = "RISK:" ascii
        $key_24 = "Subnautica:" ascii
        $key_25 = "The Elder Scrolls V:" ascii
        $key_26 = "Threads:" ascii
        $key_27 = "TimeZone:" ascii
        $key_28 = "User Name:" ascii
        $key_29 = "VideoCard:" ascii
        $key_30 = "Windows:" ascii
        $key_31 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}