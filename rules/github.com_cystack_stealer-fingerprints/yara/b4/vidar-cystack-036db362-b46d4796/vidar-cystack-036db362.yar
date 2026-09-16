rule Vidar_cystack_036db362
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_036db362"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Bro Falls:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "GUID:" ascii
        $key_8 = "HWID:" ascii
        $key_9 = "Install Date:" ascii
        $key_10 = "Ip:" ascii
        $key_11 = "Jelly Brawl:" ascii
        $key_12 = "Keyboard Languages:" ascii
        $key_13 = "Knightfall:" ascii
        $key_14 = "Local Time:" ascii
        $key_15 = "MachineID:" ascii
        $key_16 = "Maurice:" ascii
        $key_17 = "Path:" ascii
        $key_18 = "Pixel Gun 3D:" ascii
        $key_19 = "Processor:" ascii
        $key_20 = "RAM:" ascii
        $key_21 = "Rekt:" ascii
        $key_22 = "Slapshot:" ascii
        $key_23 = "Threads:" ascii
        $key_24 = "TimeZone:" ascii
        $key_25 = "User Name:" ascii
        $key_26 = "VideoCard:" ascii
        $key_27 = "Windows:" ascii
        $key_28 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}