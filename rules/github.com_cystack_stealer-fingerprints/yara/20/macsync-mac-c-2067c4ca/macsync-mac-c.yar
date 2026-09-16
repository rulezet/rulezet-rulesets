rule MacSync_mac_c
{
    meta:
        family = "MacSync"
        fingerprint_id = "mac_c"

    strings:
        $key_0 = "Build Tag:" ascii
        $key_1 = "Graphics/Displays:" ascii
        $key_2 = "Hardware:" ascii
        $key_3 = "Password:" ascii
        $key_4 = "Software:" ascii
        $key_5 = "Username:" ascii
        $key_6 = "Version:" ascii

    condition:
        all of ($key_*)
}