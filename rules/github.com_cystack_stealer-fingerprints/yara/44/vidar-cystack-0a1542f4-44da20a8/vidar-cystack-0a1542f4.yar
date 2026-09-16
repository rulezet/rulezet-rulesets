rule Vidar_cystack_0a1542f4
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_0a1542f4"

    strings:
        $key_0 = "Cores:" ascii
        $key_1 = "Date:" ascii
        $key_2 = "Display Resolution:" ascii
        $key_3 = "GUID:" ascii
        $key_4 = "HWID:" ascii
        $key_5 = "Local Time:" ascii
        $key_6 = "MachineID:" ascii
        $key_7 = "Processor:" ascii
        $key_8 = "RAM:" ascii
        $key_9 = "Threads:" ascii
        $key_10 = "User Name:" ascii
        $key_11 = "VideoCard:" ascii
        $key_12 = "Windows:" ascii

    condition:
        all of ($key_*)
}