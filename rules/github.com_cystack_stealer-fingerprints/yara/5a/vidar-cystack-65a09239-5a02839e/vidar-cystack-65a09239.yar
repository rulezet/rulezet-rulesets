rule Vidar_cystack_65a09239
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_65a09239"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Call of Duty:" ascii
        $key_2 = "Call of Duty 4:" ascii
        $key_3 = "Call to Arms - Gates of Hell:" ascii
        $key_4 = "Computer Name:" ascii
        $key_5 = "Cores:" ascii
        $key_6 = "Country:" ascii
        $key_7 = "Date:" ascii
        $key_8 = "Display Resolution:" ascii
        $key_9 = "GUID:" ascii
        $key_10 = "Grand Theft Auto IV:" ascii
        $key_11 = "HWID:" ascii
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