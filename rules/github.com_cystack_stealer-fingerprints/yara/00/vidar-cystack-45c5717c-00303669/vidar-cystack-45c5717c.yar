rule Vidar_cystack_45c5717c
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_45c5717c"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Country:" ascii
        $key_2 = "Date:" ascii
        $key_3 = "Display Resolution:" ascii
        $key_4 = "GUID:" ascii
        $key_5 = "HWID:" ascii
        $key_6 = "Install Date:" ascii
        $key_7 = "Keyboard Languages:" ascii
        $key_8 = "Local Time:" ascii
        $key_9 = "MachineID:" ascii
        $key_10 = "Path:" ascii
        $key_11 = "User Name:" ascii
        $key_12 = "Windows:" ascii
        $key_13 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}