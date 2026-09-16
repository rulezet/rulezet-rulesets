rule CSBrowersStealer_cystack_128633b4
{
    meta:
        family = "CSBrowersStealer"
        fingerprint_id = "cystack_128633b4"

    strings:
        $key_0 = "Antivirus:" ascii
        $key_1 = "Applications:" ascii
        $key_2 = "Browers:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Extensions:" ascii
        $key_5 = "IP:" ascii
        $key_6 = "Username:" ascii
        $key_7 = "Wallets:" ascii

    condition:
        all of ($key_*)
}