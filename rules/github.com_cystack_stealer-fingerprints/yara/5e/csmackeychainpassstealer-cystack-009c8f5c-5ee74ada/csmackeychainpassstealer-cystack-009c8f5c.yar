rule CSMacKeychainPassStealer_cystack_009c8f5c
{
    meta:
        family = "CSMacKeychainPassStealer"
        fingerprint_id = "cystack_009c8f5c"

    strings:
        $key_0 = "Graphics/Displays:" ascii
        $key_1 = "Hardware:" ascii
        $key_2 = "IP:" ascii
        $key_3 = "Password:" ascii
        $key_4 = "Software:" ascii
        $key_5 = "Username:" ascii

    condition:
        all of ($key_*)
}