rule Vidar_cystack_f8dba287
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_f8dba287"

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
        $key_9 = "Keyboard Languages:" ascii
        $key_10 = "Local Time:" ascii
        $key_11 = "MachineID:" ascii
        $key_12 = "Path:" ascii
        $key_13 = "User Name:" ascii
        $key_14 = "Version:" ascii
        $key_15 = "Windows:" ascii
        $key_16 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}