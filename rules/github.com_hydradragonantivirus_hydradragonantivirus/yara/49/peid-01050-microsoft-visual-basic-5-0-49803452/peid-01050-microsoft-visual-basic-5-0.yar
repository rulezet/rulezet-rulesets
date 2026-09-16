rule PEiD_01050_Microsoft_Visual_Basic_5_0_
{
    meta:
        description = "[Microsoft Visual Basic 5.0]"
        ep_only = "false"
    strings:
        $a = {FF FF FF 00 00 00 00 00 00 30 00 00 00 40 00 00 00 00 00 00}
    condition:
        $a
}