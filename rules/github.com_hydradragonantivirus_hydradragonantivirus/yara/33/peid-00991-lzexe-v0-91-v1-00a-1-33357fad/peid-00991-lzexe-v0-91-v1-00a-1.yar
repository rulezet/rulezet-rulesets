rule PEiD_00991_LZEXE_v0_91__v1_00a__1__
{
    meta:
        description = "[LZEXE v0.91, v1.00a (1)]"
        ep_only = "true"
    strings:
        $a = {06 0E 1F 8B ?? ?? ?? 8B F1 4E 89 F7}
    condition:
        $a
}