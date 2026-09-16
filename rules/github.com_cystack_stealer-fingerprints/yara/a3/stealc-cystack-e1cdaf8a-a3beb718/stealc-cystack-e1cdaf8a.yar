rule StealC_cystack_e1cdaf8a
{
    meta:
        family = "StealC"
        fingerprint_id = "cystack_e1cdaf8a"

    strings:
        $key_0 = "Age of Empires II:" ascii
        $key_1 = "All Users:" ascii
        $key_2 = "Channel with contacts:" ascii
        $key_3 = "Commission split:" ascii
        $key_4 = "Current User:" ascii
        $key_5 = "Installed Apps:" ascii
        $key_6 = "Network Info:" ascii
        $key_7 = "Process List:" ascii
        $key_8 = "System Summary:" ascii
        $key_9 = "Telegram:" ascii
        $key_10 = "WireGuard Installer:" ascii

    condition:
        all of ($key_*)
}