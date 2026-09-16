rule Vidar_cystack_6d9bebcd
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_6d9bebcd"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Black Myth:" ascii
        $key_2 = "Clair Obscur:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Date:" ascii
        $key_7 = "Display Resolution:" ascii
        $key_8 = "Divinity:" ascii
        $key_9 = "GUID:" ascii
        $key_10 = "HWID:" ascii
        $key_11 = "Half-Life 2:" ascii
        $key_12 = "Hollow Knight:" ascii
        $key_13 = "Install Date:" ascii
        $key_14 = "Ip:" ascii
        $key_15 = "Keyboard Languages:" ascii
        $key_16 = "Local Time:" ascii
        $key_17 = "METAL GEAR SOLID 3:" ascii
        $key_18 = "MachineID:" ascii
        $key_19 = "Path:" ascii
        $key_20 = "Processor:" ascii
        $key_21 = "RAM:" ascii
        $key_22 = "SCP:" ascii
        $key_23 = "The Binding of Isaac:" ascii
        $key_24 = "The Elder Scrolls V:" ascii
        $key_25 = "The Witcher:" ascii
        $key_26 = "The Witcher 2:" ascii
        $key_27 = "Threads:" ascii
        $key_28 = "TimeZone:" ascii
        $key_29 = "User Name:" ascii
        $key_30 = "VideoCard:" ascii
        $key_31 = "Windows:" ascii
        $key_32 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}