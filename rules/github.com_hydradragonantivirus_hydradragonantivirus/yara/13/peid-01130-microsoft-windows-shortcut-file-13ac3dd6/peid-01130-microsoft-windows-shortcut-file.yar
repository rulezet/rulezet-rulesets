rule PEiD_01130_Microsoft_Windows_Shortcut_file_
{
    meta:
        description = "[Microsoft Windows Shortcut file]"
        ep_only = "false"
    strings:
        $a = {4C 00 00 00 01 14 02 00 00 00}
    condition:
        $a
}