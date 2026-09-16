rule CSBrowersStealer_cystack_0120da9d
{
    meta:
        family = "CSBrowersStealer"
        fingerprint_id = "cystack_0120da9d"

    strings:
        $key_0 = "Antivirus:" ascii
        $key_1 = "Applications:" ascii
        $key_2 = "Browers:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Extensions:" ascii
        $key_5 = "Facebook:" ascii
        $key_6 = "Ip:" ascii
        $key_7 = "Username:" ascii
        $key_8 = "Wallets:" ascii

    condition:
        all of ($key_*)
}