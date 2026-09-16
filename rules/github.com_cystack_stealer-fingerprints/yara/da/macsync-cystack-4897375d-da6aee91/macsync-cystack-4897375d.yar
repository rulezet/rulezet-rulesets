rule MacSync_cystack_4897375d
{
    meta:
        family = "MacSync"
        fingerprint_id = "cystack_4897375d"

    strings:
        $key_0 = "Build Tag:" ascii
        $key_1 = "Graphics/Displays:" ascii
        $key_2 = "Hardware:" ascii
        $key_3 = "Password:" ascii
        $key_4 = "Software:" ascii
        $key_5 = "Username:" ascii

    condition:
        all of ($key_*)
}