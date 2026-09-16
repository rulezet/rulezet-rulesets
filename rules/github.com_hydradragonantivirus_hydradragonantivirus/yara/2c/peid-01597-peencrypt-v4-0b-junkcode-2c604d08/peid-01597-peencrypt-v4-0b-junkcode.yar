rule PEiD_01597_PEEncrypt_v4_0b__JunkCode__
{
    meta:
        description = "[PEEncrypt v4.0b (JunkCode)]"
        ep_only = "true"
    strings:
        $a = {66 ?? ?? 00 66 83 ?? 00}
    condition:
        $a
}