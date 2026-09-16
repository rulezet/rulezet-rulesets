rule Category_Stealer_cystack_f7ecb916
{
    meta:
        family = "Category Stealer"
        fingerprint_id = "cystack_f7ecb916"

    strings:
        $key_0 = "Category:" ascii
        $key_1 = "Country:" ascii
        $key_2 = "IP:" ascii
        $key_3 = "Path:" ascii

    condition:
        all of ($key_*)
}