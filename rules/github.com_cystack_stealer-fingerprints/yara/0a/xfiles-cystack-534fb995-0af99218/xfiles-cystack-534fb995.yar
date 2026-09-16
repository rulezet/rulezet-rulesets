rule XFiles_cystack_534fb995
{
    meta:
        family = "XFiles"
        fingerprint_id = "cystack_534fb995"

    strings:
        $key_0 = "CPU (Processor):" ascii
        $key_1 = "Channel with contacts:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Desktop Screenshot Taken:" ascii
        $key_5 = "GPU (Display Devices):" ascii
        $key_6 = "Hardware ID:" ascii
        $key_7 = "IP:" ascii
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