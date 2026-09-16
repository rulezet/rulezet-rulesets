rule PEiD_02428_UPX_Protector_v1_0x__2__
{
    meta:
        description = "[UPX Protector v1.0x (2)]"
        ep_only = "false"
    strings:
        $a = {EB ?? ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB}
    condition:
        $a
}