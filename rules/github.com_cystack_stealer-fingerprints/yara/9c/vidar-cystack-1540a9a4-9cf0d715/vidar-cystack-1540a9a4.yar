rule Vidar_cystack_1540a9a4
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_1540a9a4"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Date:" ascii
        $key_4 = "GUID:" ascii
        $key_5 = "HWID:" ascii
        $key_6 = "Install Date:" ascii
        $key_7 = "Ip:" ascii
        $key_8 = "MachineID:" ascii
        $key_9 = "Path:" ascii
        $key_10 = "User Name:" ascii
        $key_11 = "Version:" ascii
        $key_12 = "Windows:" ascii
        $key_13 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}