rule StealC_cystack_e1caec1c
{
    meta:
        family = "StealC"
        fingerprint_id = "cystack_e1caec1c"

    strings:
        $key_0 = "All Users:" ascii
        $key_1 = "Current User:" ascii
        $key_2 = "Installed Apps:" ascii
        $key_3 = "Network Info:" ascii
        $key_4 = "System Summary:" ascii
        $key_5 = "User Agents:" ascii

    condition:
        all of ($key_*)
}