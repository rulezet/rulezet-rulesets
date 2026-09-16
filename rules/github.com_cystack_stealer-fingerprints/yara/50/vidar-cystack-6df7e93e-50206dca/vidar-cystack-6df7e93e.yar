rule Vidar_cystack_6df7e93e
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_6df7e93e"

    strings:
        $key_0 = "ARK:" ascii
        $key_1 = "AV:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "Factory Outlet Simulator:" ascii
        $key_8 = "GUID:" ascii
        $key_9 = "HWID:" ascii
        $key_10 = "Install Date:" ascii
        $key_11 = "Ip:" ascii
        $key_12 = "Keyboard Languages:" ascii
        $key_13 = "Local Time:" ascii
        $key_14 = "MachineID:" ascii
        $key_15 = "NARAKA:" ascii
        $key_16 = "PUBG:" ascii
        $key_17 = "Path:" ascii
        $key_18 = "Processor:" ascii
        $key_19 = "RAM:" ascii
        $key_20 = "Seven Knights Re:" ascii
        $key_21 = "Solo Leveling:" ascii
        $key_22 = "TCG Card Shop Simulator:" ascii
        $key_23 = "Threads:" ascii
        $key_24 = "TimeZone:" ascii
        $key_25 = "User Name:" ascii
        $key_26 = "VideoCard:" ascii
        $key_27 = "Windows:" ascii
        $key_28 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}