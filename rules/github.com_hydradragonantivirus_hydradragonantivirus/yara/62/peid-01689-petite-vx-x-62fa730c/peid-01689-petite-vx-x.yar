rule PEiD_01689_PEtite_vx_x_
{
    meta:
        description = "[PEtite vx.x]"
        ep_only = "true"
    strings:
        $a = {B8 ?? ?? ?? ?? 66 9C 60 50}
    condition:
        $a
}