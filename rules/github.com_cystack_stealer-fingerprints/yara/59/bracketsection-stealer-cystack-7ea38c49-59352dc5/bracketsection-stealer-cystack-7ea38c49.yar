rule BracketSection_Stealer_cystack_7ea38c49
{
    meta:
        family = "BracketSection Stealer"
        fingerprint_id = "cystack_7ea38c49"

    strings:
        $key_0 = "Buildtag:" ascii
        $key_1 = "City:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "GPU:" ascii
        $key_4 = "Hostname:" ascii
        $key_5 = "Hwid:" ascii
        $key_6 = "IP:" ascii
        $key_7 = "Keyboard:" ascii
        $key_8 = "OS Product:" ascii
        $key_9 = "RAM:" ascii
        $key_10 = "Screensize:" ascii
        $key_11 = "System Language:" ascii
        $key_12 = "Timezone:" ascii
        $key_13 = "Username:" ascii

    condition:
        all of ($key_*)
}