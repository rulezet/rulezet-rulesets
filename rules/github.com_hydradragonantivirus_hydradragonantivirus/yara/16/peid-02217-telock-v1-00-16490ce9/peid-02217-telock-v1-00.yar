rule PEiD_02217_tElock_v1_00_
{
    meta:
        description = "[tElock v1.00]"
        ep_only = "true"
    strings:
        $a = {E9 E5 E2 FF FF}
    condition:
        $a
}