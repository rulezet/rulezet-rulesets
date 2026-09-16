rule PEiD_02214_tElock_v0_98b1_
{
    meta:
        description = "[tElock v0.98b1]"
        ep_only = "true"
    strings:
        $a = {E9 25 E4 FF FF}
    condition:
        $a
}