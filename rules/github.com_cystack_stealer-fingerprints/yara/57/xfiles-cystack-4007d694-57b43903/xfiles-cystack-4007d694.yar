rule XFiles_cystack_4007d694
{
    meta:
        family = "XFiles"
        fingerprint_id = "cystack_4007d694"

    strings:
        $key_0 = "CPU (Processor):" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Desktop Screenshot Taken:" ascii
        $key_4 = "GPU (Display Devices):" ascii
        $key_5 = "Hardware ID:" ascii
        $key_6 = "IP:" ascii
        $key_7 = "Operating System:" ascii
        $key_8 = "RAM (Memory):" ascii
        $key_9 = "Screens:" ascii
        $key_10 = "Username:" ascii

    condition:
        all of ($key_*)
}