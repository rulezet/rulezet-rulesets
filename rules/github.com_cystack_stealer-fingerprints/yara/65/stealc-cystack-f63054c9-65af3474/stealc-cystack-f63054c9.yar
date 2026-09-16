rule StealC_cystack_f63054c9
{
    meta:
        family = "StealC"
        fingerprint_id = "cystack_f63054c9"

    strings:
        $key_0 = "All Users:" ascii
        $key_1 = "Channel with contacts:" ascii
        $key_2 = "Commission split:" ascii
        $key_3 = "Installed Apps:" ascii
        $key_4 = "Network Info:" ascii
        $key_5 = "System Summary:" ascii

    condition:
        all of ($key_*)
}