rule Vidar_cystack_fe7064d8
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_fe7064d8"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Country:" ascii
        $key_2 = "Date:" ascii
        $key_3 = "Display Resolution:" ascii
        $key_4 = "GUID:" ascii
        $key_5 = "HWID:" ascii
        $key_6 = "Install Date:" ascii
        $key_7 = "Ip:" ascii
        $key_8 = "Keyboard Languages:" ascii
        $key_9 = "Local Time:" ascii
        $key_10 = "MachineID:" ascii
        $key_11 = "Path:" ascii
        $key_12 = "Processor:" ascii
        $key_13 = "TimeZone:" ascii
        $key_14 = "User Name:" ascii
        $key_15 = "Windows:" ascii
        $key_16 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}