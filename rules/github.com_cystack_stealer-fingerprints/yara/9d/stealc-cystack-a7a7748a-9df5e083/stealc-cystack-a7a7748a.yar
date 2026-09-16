rule StealC_cystack_a7a7748a
{
    meta:
        family = "StealC"
        fingerprint_id = "cystack_a7a7748a"

    strings:
        $key_0 = "All Users:" ascii
        $key_1 = "Channel with contacts:" ascii
        $key_2 = "Commission split:" ascii
        $key_3 = "Installed Apps:" ascii
        $key_4 = "MTA:" ascii
        $key_5 = "Network Info:" ascii
        $key_6 = "System Summary:" ascii
        $key_7 = "Telegram:" ascii
        $key_8 = "User Agents:" ascii

    condition:
        all of ($key_*)
}