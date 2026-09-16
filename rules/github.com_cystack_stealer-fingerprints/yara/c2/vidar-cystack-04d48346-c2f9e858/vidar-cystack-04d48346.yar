rule Vidar_cystack_04d48346
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_04d48346"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Date:" ascii
        $key_5 = "Display Resolution:" ascii
        $key_6 = "Fast Food Simulator:" ascii
        $key_7 = "GUID:" ascii
        $key_8 = "Gabenwood:" ascii
        $key_9 = "Gabenwood 3:" ascii
        $key_10 = "HWID:" ascii
        $key_11 = "Install Date:" ascii
        $key_12 = "Ip:" ascii
        $key_13 = "Keyboard Languages:" ascii
        $key_14 = "Knightfall:" ascii
        $key_15 = "Local Time:" ascii
        $key_16 = "MachineID:" ascii
        $key_17 = "NARAKA:" ascii
        $key_18 = "Navy War:" ascii
        $key_19 = "PICO PARK:" ascii
        $key_20 = "Path:" ascii
        $key_21 = "Processor:" ascii
        $key_22 = "RAM:" ascii
        $key_23 = "RISK:" ascii
        $key_24 = "The Witcher 3:" ascii
        $key_25 = "Threads:" ascii
        $key_26 = "TimeZone:" ascii
        $key_27 = "User Name:" ascii
        $key_28 = "VideoCard:" ascii
        $key_29 = "Windows:" ascii
        $key_30 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}