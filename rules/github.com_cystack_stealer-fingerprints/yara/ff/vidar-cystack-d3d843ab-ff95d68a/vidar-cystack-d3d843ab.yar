rule Vidar_cystack_d3d843ab
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_d3d843ab"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Display Resolution:" ascii
        $key_4 = "GUID:" ascii
        $key_5 = "HWID:" ascii
        $key_6 = "Install Date:" ascii
        $key_7 = "Keyboard Languages:" ascii
        $key_8 = "Local Time:" ascii
        $key_9 = "MachineID:" ascii
        $key_10 = "Processor:" ascii
        $key_11 = "RAM:" ascii
        $key_12 = "Threads:" ascii
        $key_13 = "TimeZone:" ascii
        $key_14 = "VideoCard:" ascii
        $key_15 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}