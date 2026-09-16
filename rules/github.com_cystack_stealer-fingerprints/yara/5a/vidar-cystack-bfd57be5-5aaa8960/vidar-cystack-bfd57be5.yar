rule Vidar_cystack_bfd57be5
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_bfd57be5"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Date:" ascii
        $key_5 = "Display Resolution:" ascii
        $key_6 = "IP:" ascii
        $key_7 = "Install Date:" ascii
        $key_8 = "Keyboard Languages:" ascii
        $key_9 = "Local Time:" ascii
        $key_10 = "Path:" ascii
        $key_11 = "Processor:" ascii
        $key_12 = "Quarantine Zone:" ascii
        $key_13 = "RAM:" ascii
        $key_14 = "SCP:" ascii
        $key_15 = "Schedule I:" ascii
        $key_16 = "Threads:" ascii
        $key_17 = "TimeZone:" ascii
        $key_18 = "User Name:" ascii
        $key_19 = "Version:" ascii
        $key_20 = "VideoCard:" ascii
        $key_21 = "Windows:" ascii
        $key_22 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}