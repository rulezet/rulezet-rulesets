rule WhiteSnake_cystack_3e31e88c
{
    meta:
        family = "WhiteSnake"
        fingerprint_id = "cystack_3e31e88c"

    strings:
        $key_0 = "CPU:" ascii
        $key_1 = "City:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "GPU:" ascii
        $key_4 = "IP:" ascii
        $key_5 = "Installed antivirus:" ascii
        $key_6 = "Internet provider:" ascii
        $key_7 = "RAM:" ascii
        $key_8 = "Region:" ascii
        $key_9 = "Started as admin:" ascii
        $key_10 = "System:" ascii
        $key_11 = "System time:" ascii
        $key_12 = "User name:" ascii

    condition:
        all of ($key_*)
}