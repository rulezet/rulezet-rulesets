rule Vidar_cystack_c53d1594
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_c53d1594"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Batman:" ascii
        $key_2 = "Cat Simulator:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Dark Deception:" ascii
        $key_7 = "Date:" ascii
        $key_8 = "Display Resolution:" ascii
        $key_9 = "GUID:" ascii
        $key_10 = "Grand Theft Auto:" ascii
        $key_11 = "Grand Theft Auto IV:" ascii
        $key_12 = "HWID:" ascii
        $key_13 = "Install Date:" ascii
        $key_14 = "Ip:" ascii
        $key_15 = "Keyboard Languages:" ascii
        $key_16 = "Local Time:" ascii
        $key_17 = "MachineID:" ascii
        $key_18 = "Path:" ascii
        $key_19 = "Processor:" ascii
        $key_20 = "RAM:" ascii
        $key_21 = "STAR WARS Jedi:" ascii
        $key_22 = "Threads:" ascii
        $key_23 = "TimeZone:" ascii
        $key_24 = "User Name:" ascii
        $key_25 = "Version:" ascii
        $key_26 = "VideoCard:" ascii
        $key_27 = "Windows:" ascii
        $key_28 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}