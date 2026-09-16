rule PEiD_01789_PS_AdobeFont_v_1_0_
{
    meta:
        description = "[PS-AdobeFont v.1.0]"
        ep_only = "false"
    strings:
        $a = {80 01 ?? ?? 00 00 25 21 50 53 2D 41 64 6F 62 65 46 6F 6E 74 2D 31 2E 30 3A}
    condition:
        $a
}