rule Vidar_cystack_9795b937
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_9795b937"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "COMBAT ARMS:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "GUID:" ascii
        $key_8 = "HWID:" ascii
        $key_9 = "Install Date:" ascii
        $key_10 = "Ip:" ascii
        $key_11 = "JDM:" ascii
        $key_12 = "Keyboard Languages:" ascii
        $key_13 = "Local Time:" ascii
        $key_14 = "MachineID:" ascii
        $key_15 = "No70:" ascii
        $key_16 = "Path:" ascii
        $key_17 = "Pixel Gun 3D:" ascii
        $key_18 = "Processor:" ascii
        $key_19 = "RAM:" ascii
        $key_20 = "SCP:" ascii
        $key_21 = "Soccer Online:" ascii
        $key_22 = "Supermarket Simulator:" ascii
        $key_23 = "Threads:" ascii
        $key_24 = "TimeZone:" ascii
        $key_25 = "User Name:" ascii
        $key_26 = "VideoCard:" ascii
        $key_27 = "Windows:" ascii
        $key_28 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}