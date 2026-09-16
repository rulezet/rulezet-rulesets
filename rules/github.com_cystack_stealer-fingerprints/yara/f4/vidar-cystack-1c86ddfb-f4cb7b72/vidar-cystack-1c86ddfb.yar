rule Vidar_cystack_1c86ddfb
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_1c86ddfb"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Among Us 3D:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "DRAGON BALL:" ascii
        $key_6 = "Date:" ascii
        $key_7 = "Display Resolution:" ascii
        $key_8 = "GUID:" ascii
        $key_9 = "Grand Theft Auto IV:" ascii
        $key_10 = "HWID:" ascii
        $key_11 = "Hellsplit:" ascii
        $key_12 = "Install Date:" ascii
        $key_13 = "Ip:" ascii
        $key_14 = "Keyboard Languages:" ascii
        $key_15 = "Local Time:" ascii
        $key_16 = "MachineID:" ascii
        $key_17 = "Path:" ascii
        $key_18 = "Processor:" ascii
        $key_19 = "RAM:" ascii
        $key_20 = "Threads:" ascii
        $key_21 = "TimeZone:" ascii
        $key_22 = "User Name:" ascii
        $key_23 = "VideoCard:" ascii
        $key_24 = "Windows:" ascii
        $key_25 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}