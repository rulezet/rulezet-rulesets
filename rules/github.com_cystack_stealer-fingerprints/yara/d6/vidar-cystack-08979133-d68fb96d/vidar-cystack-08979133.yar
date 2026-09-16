rule Vidar_cystack_08979133
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_08979133"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Date:" ascii
        $key_4 = "Display Resolution:" ascii
        $key_5 = "GUID:" ascii
        $key_6 = "HWID:" ascii
        $key_7 = "Install Date:" ascii
        $key_8 = "Ip:" ascii
        $key_9 = "MachineID:" ascii
        $key_10 = "Path:" ascii
        $key_11 = "User Name:" ascii
        $key_12 = "Version:" ascii
        $key_13 = "Windows:" ascii
        $key_14 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}