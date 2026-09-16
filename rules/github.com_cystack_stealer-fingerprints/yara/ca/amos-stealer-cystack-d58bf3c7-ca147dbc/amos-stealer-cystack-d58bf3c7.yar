rule AMOS_Stealer_cystack_d58bf3c7
{
    meta:
        family = "AMOS Stealer"
        fingerprint_id = "cystack_d58bf3c7"

    strings:
        $key_0 = "ATI Radeon HD 5750:" ascii
        $key_1 = "City:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Debanks:" ascii
        $key_4 = "Graphics/Displays:" ascii
        $key_5 = "Hardware:" ascii
        $key_6 = "Hardware Overview:" ascii
        $key_7 = "IP:" ascii
        $key_8 = "MetaMask Info:" ascii
        $key_9 = "Software:" ascii
        $key_10 = "System Software Overview:" ascii
        $key_11 = "Userinfo:" ascii

    condition:
        all of ($key_*)
}