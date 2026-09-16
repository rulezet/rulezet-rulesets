rule XFiles_cystack_fda4f08d
{
    meta:
        family = "XFiles"
        fingerprint_id = "cystack_fda4f08d"

    strings:
        $key_0 = "Computer Name:" ascii
        $key_1 = "Country:" ascii
        $key_2 = "Desktop Screenshot Taken:" ascii
        $key_3 = "GPU (Display Devices):" ascii
        $key_4 = "Hardware ID:" ascii
        $key_5 = "IP:" ascii
        $key_6 = "Operating System:" ascii
        $key_7 = "Processed parts:" ascii
        $key_8 = "RAM (Memory):" ascii
        $key_9 = "Screens:" ascii
        $key_10 = "Username:" ascii

    condition:
        all of ($key_*)
}