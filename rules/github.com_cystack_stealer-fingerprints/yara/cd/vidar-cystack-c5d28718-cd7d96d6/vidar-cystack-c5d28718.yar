rule Vidar_cystack_c5d28718
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_c5d28718"

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
        $key_9 = "MachineID:" ascii
        $key_10 = "Path:" ascii
        $key_11 = "User Name:" ascii
        $key_12 = "Windows:" ascii
        $key_13 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}