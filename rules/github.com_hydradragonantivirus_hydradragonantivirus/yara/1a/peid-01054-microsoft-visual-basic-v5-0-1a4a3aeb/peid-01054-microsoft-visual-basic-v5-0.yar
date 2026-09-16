rule PEiD_01054_Microsoft_Visual_Basic_v5_0_
{
    meta:
        description = "[Microsoft Visual Basic v5.0]"
        ep_only = "true"
    strings:
        $a = {?? ?? ?? ?? ?? ?? ?? FF FF FF 00 00 00 00 00 00 30 00 00 00 40 00 00 00 00 00 00}
    condition:
        $a
}