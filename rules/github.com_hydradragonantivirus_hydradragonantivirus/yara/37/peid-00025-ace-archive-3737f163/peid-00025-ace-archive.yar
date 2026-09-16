rule PEiD_00025_ACE_Archive_
{
    meta:
        description = "[ACE Archive]"
        ep_only = "false"
    strings:
        $a = {?? ?? ?? ?? ?? ?? ?? 2A 2A 41 43 45 2A 2A}
    condition:
        $a
}