rule Lumma_cystack_4476ec73
{
    meta:
        family = "Lumma"
        fingerprint_id = "cystack_4476ec73"

    strings:
        $key_0 = "Exploit:" ascii
        $key_1 = "LID(Lumma ID):" ascii
        $key_2 = "Telegram:" ascii

    condition:
        all of ($key_*)
}