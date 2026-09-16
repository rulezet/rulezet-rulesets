rule Vidar_cystack_1286183e
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_1286183e"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Command and Conquer 3:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Crime Boss:" ascii
        $key_6 = "Date:" ascii
        $key_7 = "Display Resolution:" ascii
        $key_8 = "Dying Light 2:" ascii
        $key_9 = "GUID:" ascii
        $key_10 = "HWID:" ascii
        $key_11 = "Install Date:" ascii
        $key_12 = "Ip:" ascii
        $key_13 = "Keyboard Languages:" ascii
        $key_14 = "Local Time:" ascii
        $key_15 = "MachineID:" ascii
        $key_16 = "Path:" ascii
        $key_17 = "Processor:" ascii
        $key_18 = "RAM:" ascii
        $key_19 = "RoboCop:" ascii
        $key_20 = "Threads:" ascii
        $key_21 = "TimeZone:" ascii
        $key_22 = "User Name:" ascii
        $key_23 = "Version:" ascii
        $key_24 = "VideoCard:" ascii
        $key_25 = "Windows:" ascii
        $key_26 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}