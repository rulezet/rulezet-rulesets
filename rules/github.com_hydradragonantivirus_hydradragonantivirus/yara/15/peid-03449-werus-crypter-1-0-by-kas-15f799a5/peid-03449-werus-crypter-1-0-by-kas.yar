rule PEiD_03449_Werus_Crypter_1_0___by_Kas_
{
    meta:
        description = "[Werus Crypter 1.0 - by Kas]"
        ep_only = "true"
    strings:
        $a = {BB E8 12 40 00 80 33 05 E9 7D FF FF FF}
    condition:
        $a
}