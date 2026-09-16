rule XFiles_cystack_0f754c78
{
    meta:
        family = "XFiles"
        fingerprint_id = "cystack_0f754c78"

    strings:
        $key_0 = "Computer Name:" ascii
        $key_1 = "Country:" ascii
        $key_2 = "Desktop Screenshot Taken:" ascii
        $key_3 = "GPU (Display Devices):" ascii
        $key_4 = "Hardware ID:" ascii
        $key_5 = "IP:" ascii
        $key_6 = "Operating System:" ascii
        $key_7 = "RAM (Memory):" ascii
        $key_8 = "Screens:" ascii
        $key_9 = "Username:" ascii

    condition:
        all of ($key_*)
}