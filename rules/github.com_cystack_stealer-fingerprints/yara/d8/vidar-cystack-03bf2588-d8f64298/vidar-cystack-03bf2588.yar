rule Vidar_cystack_03bf2588
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_03bf2588"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Age of Empires II:" ascii
        $key_2 = "Age of Empires IV:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Date:" ascii
        $key_7 = "Display Resolution:" ascii
        $key_8 = "GUID:" ascii
        $key_9 = "HWID:" ascii
        $key_10 = "Heroes of Might and Magic:" ascii
        $key_11 = "Hollow Knight:" ascii
        $key_12 = "Install Date:" ascii
        $key_13 = "Keyboard Languages:" ascii
        $key_14 = "Local Time:" ascii
        $key_15 = "MachineID:" ascii
        $key_16 = "Path:" ascii
        $key_17 = "Processor:" ascii
        $key_18 = "RAM:" ascii
        $key_19 = "RISK:" ascii
        $key_20 = "The Witcher 3:" ascii
        $key_21 = "Threads:" ascii
        $key_22 = "TimeZone:" ascii
        $key_23 = "User Name:" ascii
        $key_24 = "VideoCard:" ascii
        $key_25 = "Windows:" ascii
        $key_26 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}