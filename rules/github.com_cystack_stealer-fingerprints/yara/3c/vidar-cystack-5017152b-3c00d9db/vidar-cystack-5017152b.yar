rule Vidar_cystack_5017152b
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_5017152b"

    strings:
        $key_0 = "Country:" ascii
        $key_1 = "Date:" ascii

    condition:
        all of ($key_*)
}