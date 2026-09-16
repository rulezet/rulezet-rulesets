rule Vidar_cystack_8a7958a4
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_8a7958a4"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Accident:" ascii
        $key_2 = "Asphalt 9:" ascii
        $key_3 = "Call of Duty:" ascii
        $key_4 = "Computer Name:" ascii
        $key_5 = "Cores:" ascii
        $key_6 = "Country:" ascii
        $key_7 = "Dark Hours:" ascii
        $key_8 = "Date:" ascii
        $key_9 = "Display Resolution:" ascii
        $key_10 = "GUID:" ascii
        $key_11 = "HWID:" ascii
        $key_12 = "Install Date:" ascii
        $key_13 = "Ip:" ascii
        $key_14 = "JDM:" ascii
        $key_15 = "Keyboard Languages:" ascii
        $key_16 = "Local Time:" ascii
        $key_17 = "MachineID:" ascii
        $key_18 = "PUBG:" ascii
        $key_19 = "Path:" ascii
        $key_20 = "Processor:" ascii
        $key_21 = "RAM:" ascii
        $key_22 = "Threads:" ascii
        $key_23 = "TimeZone:" ascii
        $key_24 = "User Name:" ascii
        $key_25 = "VideoCard:" ascii
        $key_26 = "Windows:" ascii
        $key_27 = "Work Dir:" ascii
        $key_28 = "Wrap House Simulator:" ascii

    condition:
        all of ($key_*)
}