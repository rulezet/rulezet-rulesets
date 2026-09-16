rule Vidar_cystack_42a0987a
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_42a0987a"

    strings:
        $key_0 = "Computer Name:" ascii
        $key_1 = "Cores:" ascii
        $key_2 = "Display Resolution:" ascii
        $key_3 = "GUID:" ascii
        $key_4 = "HWID:" ascii
        $key_5 = "Local Time:" ascii
        $key_6 = "MachineID:" ascii
        $key_7 = "Path:" ascii
        $key_8 = "Processor:" ascii
        $key_9 = "RAM:" ascii
        $key_10 = "Threads:" ascii
        $key_11 = "User Name:" ascii
        $key_12 = "VideoCard:" ascii
        $key_13 = "Windows:" ascii
        $key_14 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}