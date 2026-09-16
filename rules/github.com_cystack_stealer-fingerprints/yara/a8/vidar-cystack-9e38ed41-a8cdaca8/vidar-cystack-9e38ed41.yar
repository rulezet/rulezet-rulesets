rule Vidar_cystack_9e38ed41
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_9e38ed41"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Batman:" ascii
        $key_2 = "Bombergrounds:" ascii
        $key_3 = "Cafe Owner Simulator:" ascii
        $key_4 = "Car Detailing Simulator:" ascii
        $key_5 = "Computer Name:" ascii
        $key_6 = "Cores:" ascii
        $key_7 = "Country:" ascii
        $key_8 = "Date:" ascii
        $key_9 = "Display Resolution:" ascii
        $key_10 = "GUID:" ascii
        $key_11 = "HWID:" ascii
        $key_12 = "Hotdog:" ascii
        $key_13 = "Install Date:" ascii
        $key_14 = "Ip:" ascii
        $key_15 = "Keyboard Languages:" ascii
        $key_16 = "Local Time:" ascii
        $key_17 = "MachineID:" ascii
        $key_18 = "Passpartout:" ascii
        $key_19 = "Passpartout 2:" ascii
        $key_20 = "Path:" ascii
        $key_21 = "Prison Escape Simulator:" ascii
        $key_22 = "Processor:" ascii
        $key_23 = "Quarantine Zone:" ascii
        $key_24 = "RAM:" ascii
        $key_25 = "Threads:" ascii
        $key_26 = "TimeZone:" ascii
        $key_27 = "User Name:" ascii
        $key_28 = "VideoCard:" ascii
        $key_29 = "Windows:" ascii
        $key_30 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}