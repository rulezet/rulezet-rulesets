rule Arcane_cystack_c527b366
{
    meta:
        family = "Arcane"
        fingerprint_id = "cystack_c527b366"

    strings:
        $key_0 = "Destinatar:" ascii
        $key_1 = "Mesaj:" ascii

    condition:
        all of ($key_*)
}