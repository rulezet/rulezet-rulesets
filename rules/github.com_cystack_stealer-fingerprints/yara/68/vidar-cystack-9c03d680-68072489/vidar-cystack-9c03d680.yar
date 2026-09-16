rule Vidar_cystack_9c03d680
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_9c03d680"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Country:" ascii
        $key_2 = "Date:" ascii
        $key_3 = "GUID:" ascii
        $key_4 = "HWID:" ascii
        $key_5 = "Install Date:" ascii
        $key_6 = "Ip:" ascii
        $key_7 = "MachineID:" ascii
        $key_8 = "Path:" ascii
        $key_9 = "User Name:" ascii
        $key_10 = "Windows:" ascii
        $key_11 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}