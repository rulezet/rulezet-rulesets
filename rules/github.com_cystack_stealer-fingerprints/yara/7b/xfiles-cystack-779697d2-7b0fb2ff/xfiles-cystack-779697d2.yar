rule XFiles_cystack_779697d2
{
    meta:
        family = "XFiles"
        fingerprint_id = "cystack_779697d2"

    strings:
        $key_0 = "CPU (Processor):" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Desktop Screenshot Taken:" ascii
        $key_4 = "GPU (Display Devices):" ascii
        $key_5 = "Hardware ID:" ascii
        $key_6 = "IP:" ascii
        $key_7 = "Operating System:" ascii
        $key_8 = "Operation ID:" ascii
        $key_9 = "RAM (Memory):" ascii
        $key_10 = "Screens:" ascii
        $key_11 = "Username:" ascii

    condition:
        all of ($key_*)
}