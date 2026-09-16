rule PEiD_00895_HQR_data_file_
{
    meta:
        description = "[HQR data file]"
        ep_only = "false"
    strings:
        $a = {48 00 00 00 ?? 02 00 00 ?? ?? 00 00 ?? ?? 00 00}
    condition:
        $a
}