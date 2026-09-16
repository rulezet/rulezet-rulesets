rule StealC_cystack_0b0d0cfe
{
    meta:
        family = "StealC"
        fingerprint_id = "cystack_0b0d0cfe"

    strings:
        $key_0 = "All Users:" ascii
        $key_1 = "Current User:" ascii
        $key_2 = "Installed Apps:" ascii
        $key_3 = "Process List:" ascii
        $key_4 = "Process count:" ascii

    condition:
        all of ($key_*)
}