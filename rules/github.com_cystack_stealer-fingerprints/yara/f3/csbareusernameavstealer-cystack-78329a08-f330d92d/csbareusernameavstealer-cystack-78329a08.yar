rule CSBareUsernameAVStealer_cystack_78329a08
{
    meta:
        family = "CSBareUsernameAVStealer"
        fingerprint_id = "cystack_78329a08"

    strings:
        $key_0 = "AntiVirus:" ascii
        $key_1 = "IP:" ascii
        $key_2 = "Username:" ascii

    condition:
        all of ($key_*)
}