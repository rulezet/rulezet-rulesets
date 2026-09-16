rule Vidar_cystack_1680ef55
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_1680ef55"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Country:" ascii
        $key_2 = "Date:" ascii
        $key_3 = "Display Resolution:" ascii
        $key_4 = "GUID:" ascii
        $key_5 = "HWID:" ascii
        $key_6 = "Install Date:" ascii
        $key_7 = "Keyboard Languages:" ascii
        $key_8 = "MachineID:" ascii
        $key_9 = "Path:" ascii
        $key_10 = "User Name:" ascii
        $key_11 = "Windows:" ascii
        $key_12 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}