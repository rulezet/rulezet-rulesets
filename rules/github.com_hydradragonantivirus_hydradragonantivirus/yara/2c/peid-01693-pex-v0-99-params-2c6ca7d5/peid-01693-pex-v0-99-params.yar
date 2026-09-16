import "pe"
rule PEiD_01693_pex_V0_99____params_
{
    meta:
        description = "[pex V0.99 -> params]"
        ep_only = "true"
    strings:
        $a = {E9 F5 00 00 00}
    condition:
        $a at pe.entry_point
}