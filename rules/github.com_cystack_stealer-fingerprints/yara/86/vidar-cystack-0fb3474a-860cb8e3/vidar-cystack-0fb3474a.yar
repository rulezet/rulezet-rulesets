rule Vidar_cystack_0fb3474a
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_0fb3474a"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Black Myth:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Contra:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Date:" ascii
        $key_7 = "Display Resolution:" ascii
        $key_8 = "GUID:" ascii
        $key_9 = "HWID:" ascii
        $key_10 = "Hollow Knight:" ascii
        $key_11 = "Install Date:" ascii
        $key_12 = "Ip:" ascii
        $key_13 = "Keyboard Languages:" ascii
        $key_14 = "Local Time:" ascii
        $key_15 = "MachineID:" ascii
        $key_16 = "Mandragora:" ascii
        $key_17 = "Path:" ascii
        $key_18 = "Processor:" ascii
        $key_19 = "RAM:" ascii
        $key_20 = "SHINOBI:" ascii
        $key_21 = "Threads:" ascii
        $key_22 = "TimeZone:" ascii
        $key_23 = "Twelves:" ascii
        $key_24 = "User Name:" ascii
        $key_25 = "VideoCard:" ascii
        $key_26 = "Windows:" ascii
        $key_27 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}