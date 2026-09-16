rule AMOS_Stealer_cystack_934540d9
{
    meta:
        family = "AMOS Stealer"
        fingerprint_id = "cystack_934540d9"

    strings:
        $key_0 = "BuildVersion:" ascii
        $key_1 = "City:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Debanks:" ascii
        $key_4 = "Graphics/Displays:" ascii
        $key_5 = "Hardware:" ascii
        $key_6 = "IP:" ascii
        $key_7 = "MetaMask Info:" ascii
        $key_8 = "Private Keys:" ascii
        $key_9 = "ProductName:" ascii
        $key_10 = "ProductVersion:" ascii
        $key_11 = "Seeds:" ascii
        $key_12 = "Userinfo:" ascii

    condition:
        all of ($key_*)
}