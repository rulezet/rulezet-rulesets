rule Raccoon_cystack_a913a5d3
{
    meta:
        family = "Raccoon"
        fingerprint_id = "cystack_a913a5d3"

    strings:
        $key_0 = "Build compile date:" ascii
        $key_1 = "Installed Apps:" ascii
        $key_2 = "Launched at:" ascii
        $key_3 = "System Information:" ascii

    condition:
        all of ($key_*)
}