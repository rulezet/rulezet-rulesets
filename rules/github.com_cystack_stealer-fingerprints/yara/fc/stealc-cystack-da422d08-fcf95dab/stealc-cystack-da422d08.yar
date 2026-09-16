rule StealC_cystack_da422d08
{
    meta:
        family = "StealC"
        fingerprint_id = "cystack_da422d08"

    strings:
        $key_0 = "All Users:" ascii
        $key_1 = "Installed Apps:" ascii
        $key_2 = "Network Info:" ascii
        $key_3 = "System Summary:" ascii
        $key_4 = "User Agents:" ascii

    condition:
        all of ($key_*)
}