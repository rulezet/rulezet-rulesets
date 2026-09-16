rule PEiD_02151_StarForce_V3_X____StarForce_Copy_Protection_System_
{
    meta:
        description = "[StarForce V3.X -> StarForce Copy Protection System]"
        ep_only = "true"
    strings:
        $a = {68 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? 00 00 00 00 00}
    condition:
        $a
}