rule XFiles_cystack_a4048dad
{
    meta:
        family = "XFiles"
        fingerprint_id = "cystack_a4048dad"

    strings:
        $key_0 = "CPU (Processor):" ascii
        $key_1 = "Country:" ascii
        $key_2 = "Desktop Screenshot Taken:" ascii
        $key_3 = "GPU (Display Devices):" ascii
        $key_4 = "Hardware ID:" ascii
        $key_5 = "IP:" ascii
        $key_6 = "Operating System:" ascii
        $key_7 = "Operation ID:" ascii
        $key_8 = "Processed parts:" ascii
        $key_9 = "RAM (Memory):" ascii
        $key_10 = "Screens:" ascii
        $key_11 = "Username:" ascii

    condition:
        all of ($key_*)
}