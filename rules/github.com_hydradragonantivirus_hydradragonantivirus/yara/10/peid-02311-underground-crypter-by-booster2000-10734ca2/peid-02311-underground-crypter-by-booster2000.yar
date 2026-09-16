rule PEiD_02311_UnderGround_Crypter___by_Booster2000_
{
    meta:
        description = "[UnderGround Crypter - by Booster2000]"
        ep_only = "true"
    strings:
        $a = {55 8B EC 83 C4 F0 B8 74 3C 00 11 E8 94 F9 FF FF E8 BF FE FF FF E8 0A F3 FF FF 8B C0}
    condition:
        $a
}