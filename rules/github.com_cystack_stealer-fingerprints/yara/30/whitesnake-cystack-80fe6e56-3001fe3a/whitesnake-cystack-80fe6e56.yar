rule WhiteSnake_cystack_80fe6e56
{
    meta:
        family = "WhiteSnake"
        fingerprint_id = "cystack_80fe6e56"

    strings:
        $key_0 = "CPU:" ascii
        $key_1 = "City:" ascii
        $key_2 = "Computer name:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "GPU:" ascii
        $key_5 = "HWID:" ascii
        $key_6 = "IP:" ascii
        $key_7 = "Installed antivirus:" ascii
        $key_8 = "Internet provider:" ascii
        $key_9 = "RAM:" ascii
        $key_10 = "Region:" ascii
        $key_11 = "Started as admin:" ascii
        $key_12 = "System:" ascii
        $key_13 = "System time:" ascii
        $key_14 = "User name:" ascii

    condition:
        all of ($key_*)
}