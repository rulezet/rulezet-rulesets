rule StealC_cystack_6afce0a1
{
    meta:
        family = "StealC"
        fingerprint_id = "cystack_6afce0a1"

    strings:
        $key_0 = "All Users:" ascii
        $key_1 = "Current User:" ascii
        $key_2 = "Installed Apps:" ascii
        $key_3 = "Network Info:" ascii
        $key_4 = "Process List:" ascii
        $key_5 = "System Summary:" ascii
        $key_6 = "User Agents:" ascii

    condition:
        all of ($key_*)
}