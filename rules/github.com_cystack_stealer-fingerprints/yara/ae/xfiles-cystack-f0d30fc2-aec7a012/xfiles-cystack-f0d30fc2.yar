rule XFiles_cystack_f0d30fc2
{
    meta:
        family = "XFiles"
        fingerprint_id = "cystack_f0d30fc2"

    strings:
        $key_0 = "CPU (Processor):" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Desktop Screenshot Taken:" ascii
        $key_4 = "GPU (Display Devices):" ascii
        $key_5 = "Hardware ID:" ascii
        $key_6 = "IP:" ascii
        $key_7 = "Jabber:" ascii
        $key_8 = "Operating System:" ascii
        $key_9 = "Operation ID:" ascii
        $key_10 = "Processed parts:" ascii
        $key_11 = "RAM (Memory):" ascii
        $key_12 = "Screens:" ascii
        $key_13 = "Telegram:" ascii
        $key_14 = "Username:" ascii

    condition:
        all of ($key_*)
}