rule Lumma_cystack_9c2cb21e
{
    meta:
        family = "Lumma"
        fingerprint_id = "cystack_9c2cb21e"

    strings:
        $key_0 = "Boot Time 2025-02-26 13:" ascii
        $key_1 = "Installation Time 2022-07-02 13:" ascii
        $key_2 = "Key Type Volume:" ascii
        $key_3 = "OS Root C:" ascii

    condition:
        all of ($key_*)
}