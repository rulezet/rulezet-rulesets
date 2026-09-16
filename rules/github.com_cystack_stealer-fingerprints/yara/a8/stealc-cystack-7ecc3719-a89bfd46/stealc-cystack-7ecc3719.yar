rule StealC_cystack_7ecc3719
{
    meta:
        family = "StealC"
        fingerprint_id = "cystack_7ecc3719"

    strings:
        $key_0 = "All Users:" ascii
        $key_1 = "Channel with contacts:" ascii
        $key_2 = "Commission split:" ascii
        $key_3 = "Current User:" ascii
        $key_4 = "Installed Apps:" ascii
        $key_5 = "Network Info:" ascii
        $key_6 = "Process List:" ascii
        $key_7 = "System Summary:" ascii
        $key_8 = "Telegram:" ascii
        $key_9 = "User Agents:" ascii

    condition:
        all of ($key_*)
}