rule Vidar_cystack_18a0e59f
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_18a0e59f"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Battle Realms:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Counter-Strike:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "DRAGON BALL:" ascii
        $key_7 = "Date:" ascii
        $key_8 = "Display Resolution:" ascii
        $key_9 = "GUID:" ascii
        $key_10 = "HWID:" ascii
        $key_11 = "Install Date:" ascii
        $key_12 = "Ip:" ascii
        $key_13 = "Keyboard Languages:" ascii
        $key_14 = "Local Time:" ascii
        $key_15 = "MachineID:" ascii
        $key_16 = "Monster Hunter:" ascii
        $key_17 = "PICO PARK:" ascii
        $key_18 = "PUBG:" ascii
        $key_19 = "Path:" ascii
        $key_20 = "Processor:" ascii
        $key_21 = "RAM:" ascii
        $key_22 = "Supermarket Simulator:" ascii
        $key_23 = "Threads:" ascii
        $key_24 = "TimeZone:" ascii
        $key_25 = "Trine 4:" ascii
        $key_26 = "User Name:" ascii
        $key_27 = "VideoCard:" ascii
        $key_28 = "Windows:" ascii
        $key_29 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}