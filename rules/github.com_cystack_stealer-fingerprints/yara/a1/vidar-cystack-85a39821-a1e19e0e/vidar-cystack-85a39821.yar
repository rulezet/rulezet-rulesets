rule Vidar_cystack_85a39821
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_85a39821"

    strings:
        $key_0 = "Build:" ascii
        $key_1 = "CPU Count:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Date:" ascii
        $key_4 = "Display Language:" ascii
        $key_5 = "Display Resolution:" ascii
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
        $key_17 = "Tomb Raider:" ascii
        $key_18 = "User Name:" ascii
        $key_19 = "Version:" ascii
        $key_20 = "Windows:" ascii
        $key_21 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}