rule WhiteSnake_cystack_a11b2a84
{
    meta:
        family = "WhiteSnake"
        fingerprint_id = "cystack_a11b2a84"

    strings:
        $key_0 = "CPU:" ascii
        $key_1 = "Computer name:" ascii
        $key_2 = "GPU:" ascii
        $key_3 = "HWID:" ascii
        $key_4 = "Installed antivirus:" ascii
        $key_5 = "RAM:" ascii
        $key_6 = "Started as admin:" ascii
        $key_7 = "System:" ascii
        $key_8 = "System time:" ascii
        $key_9 = "User name:" ascii

    condition:
        all of ($key_*)
}