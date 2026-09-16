rule PEiD_00276_AVI_movie_file_
{
    meta:
        description = "[AVI movie file]"
        ep_only = "false"
    strings:
        $a = {52 49 46 46 ?? ?? ?? ?? 41 56 49 ?? 4C 49 53 54}
    condition:
        $a
}