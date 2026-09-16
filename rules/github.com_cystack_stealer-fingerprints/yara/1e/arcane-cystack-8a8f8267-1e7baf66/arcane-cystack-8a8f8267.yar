rule Arcane_cystack_8a8f8267
{
    meta:
        family = "Arcane"
        fingerprint_id = "cystack_8a8f8267"

    strings:
        $key_0 = "Rendering thread exception:" ascii
        $key_1 = "Unhandled Exception:" ascii

    condition:
        all of ($key_*)
}