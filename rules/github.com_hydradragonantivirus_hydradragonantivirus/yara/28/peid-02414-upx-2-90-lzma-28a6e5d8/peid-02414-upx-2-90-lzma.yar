rule PEiD_02414_UPX_2_90__LZMA__
{
    meta:
        description = "[UPX 2.90 (LZMA)]"
        ep_only = "true"
    strings:
        $a = {60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB}
    condition:
        $a
}