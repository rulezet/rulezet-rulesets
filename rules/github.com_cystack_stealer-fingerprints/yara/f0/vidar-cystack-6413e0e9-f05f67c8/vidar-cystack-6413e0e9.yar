rule Vidar_cystack_6413e0e9
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_6413e0e9"

    strings:
        $key_0 = "CPU Count:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Date:" ascii
        $key_3 = "Display Language:" ascii
        $key_4 = "Display Resolution:" ascii
        $key_5 = "GTA:" ascii
        $key_6 = "GUID:" ascii
        $key_7 = "HWID:" ascii
        $key_8 = "IP:" ascii
        $key_9 = "Keyboard Languages:" ascii
        $key_10 = "Local Time:" ascii
        $key_11 = "Location:" ascii
        $key_12 = "MachineID:" ascii
        $key_13 = "Path:" ascii
        $key_14 = "Processor:" ascii
        $key_15 = "RAM:" ascii
        $key_16 = "TimeZone:" ascii
        $key_17 = "User Name:" ascii
        $key_18 = "Version:" ascii
        $key_19 = "Windows:" ascii
        $key_20 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}