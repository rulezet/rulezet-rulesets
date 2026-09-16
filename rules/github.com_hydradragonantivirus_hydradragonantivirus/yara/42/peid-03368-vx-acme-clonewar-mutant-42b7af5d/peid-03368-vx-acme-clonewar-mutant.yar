rule PEiD_03368_Vx__ACME__Clonewar_Mutant__ {
  meta:
    description = "[Vx: ACME (Clonewar Mutant)]"
    ep_only     = "true"

  strings:
    $a = { FC AD 3D FF FF 74 20 E6 42 8A C4 E6 42 E4 61 0C 03 E6 61 AD B9 40 1F E2 FE }

  condition:
    $a
}