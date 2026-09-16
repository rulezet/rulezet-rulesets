rule Vidar_cystack_124f4750
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_124f4750"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Bully:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Detroit:" ascii
        $key_7 = "Display Resolution:" ascii
        $key_8 = "Duck Detective:" ascii
        $key_9 = "Dungeon Tycoon:" ascii
        $key_10 = "GUID:" ascii
        $key_11 = "HWID:" ascii
        $key_12 = "Install Date:" ascii
        $key_13 = "Ip:" ascii
        $key_14 = "Keyboard Languages:" ascii
        $key_15 = "Knightfall:" ascii
        $key_16 = "Local Time:" ascii
        $key_17 = "MachineID:" ascii
        $key_18 = "PAYDAY 2:" ascii
        $key_19 = "Path:" ascii
        $key_20 = "Processor:" ascii
        $key_21 = "RAM:" ascii
        $key_22 = "Subnautica:" ascii
        $key_23 = "Threads:" ascii
        $key_24 = "Tick Tock:" ascii
        $key_25 = "TimeZone:" ascii
        $key_26 = "User Name:" ascii
        $key_27 = "Version:" ascii
        $key_28 = "VideoCard:" ascii
        $key_29 = "We Were Here Expeditions:" ascii
        $key_30 = "Windows:" ascii
        $key_31 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}