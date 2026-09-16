rule PEiD_00055_Alias_PIX_Vivid_IMG_Graphics_format_
{
    meta:
        description = "[Alias PIX/Vivid IMG Graphics format]"
        ep_only = "false"
    strings:
        $a = {?? ?? ?? ?? 00 00 ?? ?? 00 18 ?? ?? ?? ?? 01}
    condition:
        $a
}