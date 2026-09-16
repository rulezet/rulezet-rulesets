rule Vidar_cystack_85b89979
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_85b89979"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Battle Realms:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Counter-Strike:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Date:" ascii
        $key_7 = "Display Resolution:" ascii
        $key_8 = "GUID:" ascii
        $key_9 = "Grand Theft Auto:" ascii
        $key_10 = "HWID:" ascii
        $key_11 = "Install Date:" ascii
        $key_12 = "Ip:" ascii
        $key_13 = "Keyboard Languages:" ascii
        $key_14 = "Local Time:" ascii
        $key_15 = "MachineID:" ascii
        $key_16 = "NARUTO SHIPPUDEN:" ascii
        $key_17 = "Path:" ascii
        $key_18 = "Plague Inc:" ascii
        $key_19 = "Processor:" ascii
        $key_20 = "Propagation:" ascii
        $key_21 = "RAM:" ascii
        $key_22 = "The Walking Dead:" ascii
        $key_23 = "Threads:" ascii
        $key_24 = "TimeZone:" ascii
        $key_25 = "User Name:" ascii
        $key_26 = "VideoCard:" ascii
        $key_27 = "Windows:" ascii
        $key_28 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}