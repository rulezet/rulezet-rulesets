rule StealC_cystack_81f28654
{
    meta:
        family = "StealC"
        fingerprint_id = "cystack_81f28654"

    strings:
        $key_0 = "All Users:" ascii
        $key_1 = "Current User:" ascii
        $key_2 = "Installed Apps:" ascii
        $key_3 = "Jabber:" ascii
        $key_4 = "Network Info:" ascii
        $key_5 = "System Summary:" ascii
        $key_6 = "Telegram:" ascii
        $key_7 = "User Agents:" ascii

    condition:
        all of ($key_*)
}