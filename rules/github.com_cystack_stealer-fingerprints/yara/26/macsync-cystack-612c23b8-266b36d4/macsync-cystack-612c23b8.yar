rule MacSync_cystack_612c23b8
{
    meta:
        family = "MacSync"
        fingerprint_id = "cystack_612c23b8"

    strings:
        $key_0 = "Build Tag:" ascii
        $key_1 = "Graphics/Displays:" ascii
        $key_2 = "Hardware:" ascii
        $key_3 = "IP:" ascii
        $key_4 = "Password:" ascii
        $key_5 = "Software:" ascii
        $key_6 = "Username:" ascii
        $key_7 = "Version:" ascii

    condition:
        all of ($key_*)
}