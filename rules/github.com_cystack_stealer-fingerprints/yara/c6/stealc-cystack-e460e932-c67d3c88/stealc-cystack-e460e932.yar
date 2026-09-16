rule StealC_cystack_e460e932
{
    meta:
        family = "StealC"
        fingerprint_id = "cystack_e460e932"

    strings:
        $key_0 = "Installed Apps:" ascii
        $key_1 = "Process List:" ascii
        $key_2 = "Process count:" ascii
        $key_3 = "System Summary:" ascii

    condition:
        all of ($key_*)
}