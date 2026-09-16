rule Vidar_cystack_161fae7d
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_161fae7d"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Batman:" ascii
        $key_2 = "Call of Duty:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "Dying Light:" ascii
        $key_8 = "Far Cry:" ascii
        $key_9 = "GTA:" ascii
        $key_10 = "GTA IV:" ascii
        $key_11 = "GUID:" ascii
        $key_12 = "Goat Simulator:" ascii
        $key_13 = "HWID:" ascii
        $key_14 = "Install Date:" ascii
        $key_15 = "Ip:" ascii
        $key_16 = "Keyboard Languages:" ascii
        $key_17 = "Local Time:" ascii
        $key_18 = "MachineID:" ascii
        $key_19 = "Path:" ascii
        $key_20 = "Processor:" ascii
        $key_21 = "RAM:" ascii
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