rule BracketSection_Stealer_cystack_2784c1d7
{
    meta:
        family = "BracketSection Stealer"
        fingerprint_id = "cystack_2784c1d7"

    strings:
        $key_0 = "Buildtag:" ascii
        $key_1 = "CPU:" ascii
        $key_2 = "City:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "GPU:" ascii
        $key_5 = "Hostname:" ascii
        $key_6 = "Hwid:" ascii
        $key_7 = "IP:" ascii
        $key_8 = "Keyboard:" ascii
        $key_9 = "OS Product:" ascii
        $key_10 = "RAM:" ascii
        $key_11 = "Screensize:" ascii
        $key_12 = "System Language:" ascii
        $key_13 = "Timezone:" ascii
        $key_14 = "Username:" ascii

    condition:
        all of ($key_*)
}