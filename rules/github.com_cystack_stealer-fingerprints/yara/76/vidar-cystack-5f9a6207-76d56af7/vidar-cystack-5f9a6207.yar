rule Vidar_cystack_5f9a6207
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_5f9a6207"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Azkend 2:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "Entwined:" ascii
        $key_8 = "Family Vacation 2:" ascii
        $key_9 = "GUID:" ascii
        $key_10 = "HWID:" ascii
        $key_11 = "IGT Slots:" ascii
        $key_12 = "Imperial Island:" ascii
        $key_13 = "Install Date:" ascii
        $key_14 = "Ip:" ascii
        $key_15 = "Keyboard Languages:" ascii
        $key_16 = "Local Time:" ascii
        $key_17 = "Lost Souls:" ascii
        $key_18 = "MachineID:" ascii
        $key_19 = "Mystery Expedition:" ascii
        $key_20 = "Path:" ascii
        $key_21 = "Processor:" ascii
        $key_22 = "RAM:" ascii
        $key_23 = "Threads:" ascii
        $key_24 = "TimeZone:" ascii
        $key_25 = "User Name:" ascii
        $key_26 = "Version:" ascii
        $key_27 = "VideoCard:" ascii
        $key_28 = "Windows:" ascii
        $key_29 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}