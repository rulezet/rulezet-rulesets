rule StealC_cystack_2eb9685e
{
    meta:
        family = "StealC"
        fingerprint_id = "cystack_2eb9685e"

    strings:
        $key_0 = "Installed Apps:" ascii
        $key_1 = "Network Info:" ascii
        $key_2 = "Process List:" ascii
        $key_3 = "Process count:" ascii
        $key_4 = "System Summary:" ascii

    condition:
        all of ($key_*)
}