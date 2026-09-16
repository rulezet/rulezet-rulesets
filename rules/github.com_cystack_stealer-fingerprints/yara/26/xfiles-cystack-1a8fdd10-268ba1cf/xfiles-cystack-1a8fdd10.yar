rule XFiles_cystack_1a8fdd10
{
    meta:
        family = "XFiles"
        fingerprint_id = "cystack_1a8fdd10"

    strings:
        $key_0 = "CPU (Processor):" ascii
        $key_1 = "Country:" ascii
        $key_2 = "Desktop Screenshot Taken:" ascii
        $key_3 = "GPU (Display Devices):" ascii
        $key_4 = "Hardware ID:" ascii
        $key_5 = "IP:" ascii
        $key_6 = "Operating System:" ascii
        $key_7 = "Operation ID:" ascii
        $key_8 = "RAM (Memory):" ascii
        $key_9 = "Screens:" ascii
        $key_10 = "Username:" ascii

    condition:
        all of ($key_*)
}