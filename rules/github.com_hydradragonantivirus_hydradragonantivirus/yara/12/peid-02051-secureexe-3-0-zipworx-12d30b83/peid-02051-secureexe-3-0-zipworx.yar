rule PEiD_02051_SecureEXE_3_0____ZipWorx_
{
    meta:
        description = "[SecureEXE 3.0 -> ZipWorx]"
        ep_only = "true"
    strings:
        $a = {E9 B8 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 00}
    condition:
        $a
}