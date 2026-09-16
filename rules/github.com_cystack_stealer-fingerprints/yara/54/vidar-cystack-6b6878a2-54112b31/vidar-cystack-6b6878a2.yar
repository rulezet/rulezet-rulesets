rule Vidar_cystack_6b6878a2
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_6b6878a2"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Age of Empires:" ascii
        $key_2 = "Age of Mythology:" ascii
        $key_3 = "Battlefield:" ascii
        $key_4 = "Computer Name:" ascii
        $key_5 = "Cores:" ascii
        $key_6 = "Country:" ascii
        $key_7 = "Display Resolution:" ascii
        $key_8 = "GUID:" ascii
        $key_9 = "HWID:" ascii
        $key_10 = "Install Date:" ascii
        $key_11 = "Ip:" ascii
        $key_12 = "Keyboard Languages:" ascii
        $key_13 = "Local Time:" ascii
        $key_14 = "MachineID:" ascii
        $key_15 = "Path:" ascii
        $key_16 = "Processor:" ascii
        $key_17 = "RAM:" ascii
        $key_18 = "South Park:" ascii
        $key_19 = "Threads:" ascii
        $key_20 = "TimeZone:" ascii
        $key_21 = "User Name:" ascii
        $key_22 = "Version:" ascii
        $key_23 = "VideoCard:" ascii
        $key_24 = "Windows:" ascii
        $key_25 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}