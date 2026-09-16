rule PEiD_00520_Encapsulated_Postscript_graphics_file_v3_0_EPSF_3_0_
{
    meta:
        description = "[Encapsulated Postscript graphics file v3.0 EPSF-3.0]"
        ep_only = "false"
    strings:
        $a = {25 21 50 53 2D 41 64 6F 62 65 2D 33 2E 30 20 45 50 53 46 2D 33 2E 30}
    condition:
        $a
}