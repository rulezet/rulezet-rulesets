rule PEiD_00902_IBM_PictureMaker_graphics_file_
{
    meta:
        description = "[IBM PictureMaker graphics file]"
        ep_only = "false"
    strings:
        $a = {00 ?? C1 ?? 00 ?? ?? ?? ?? 02 00 01}
    condition:
        $a
}