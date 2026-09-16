rule Vidar_cystack_5fa73c32
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_5fa73c32"

    strings:
        $key_0 = "Country:" ascii
        $key_1 = "Date:" ascii
        $key_2 = "GUID:" ascii
        $key_3 = "HWID:" ascii
        $key_4 = "Ip:" ascii
        $key_5 = "MachineID:" ascii
        $key_6 = "Version:" ascii

    condition:
        all of ($key_*)
}