rule Category_Stealer_cystack_c6900358
{
    meta:
        family = "Category Stealer"
        fingerprint_id = "cystack_c6900358"

    strings:
        $key_0 = "Category:" ascii
        $key_1 = "Country:" ascii
        $key_2 = "IP:" ascii

    condition:
        all of ($key_*)
}