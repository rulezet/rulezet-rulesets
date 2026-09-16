rule Vidar_cystack_ac9dee93
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_ac9dee93"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Beyond:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "GUID:" ascii
        $key_8 = "HWID:" ascii
        $key_9 = "Hollow Knight:" ascii
        $key_10 = "Hotline Miami 2:" ascii
        $key_11 = "Install Date:" ascii
        $key_12 = "Ip:" ascii
        $key_13 = "Keyboard Languages:" ascii
        $key_14 = "Local Time:" ascii
        $key_15 = "METAL GEAR RISING:" ascii
        $key_16 = "MachineID:" ascii
        $key_17 = "NARUTO SHIPPUDEN:" ascii
        $key_18 = "PICO PARK:" ascii
        $key_19 = "Path:" ascii
        $key_20 = "Processor:" ascii
        $key_21 = "RAM:" ascii
        $key_22 = "Resident Evil 7 Teaser:" ascii
        $key_23 = "The Binding of Isaac:" ascii
        $key_24 = "Threads:" ascii
        $key_25 = "TimeZone:" ascii
        $key_26 = "User Name:" ascii
        $key_27 = "VideoCard:" ascii
        $key_28 = "Windows:" ascii
        $key_29 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}