rule Vidar_cystack_9c394763
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_9c394763"

    strings:
        $key_0 = "Date:" ascii
        $key_1 = "GUID:" ascii
        $key_2 = "HWID:" ascii
        $key_3 = "MachineID:" ascii
        $key_4 = "Path:" ascii

    condition:
        all of ($key_*)
}