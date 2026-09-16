rule PEiD_02368_Upack_v0_1x___v0_2x____Dwing_ {
  meta:
    description = "[Upack v0.1x - v0.2x -> Dwing]"
    ep_only     = "true"

  strings:
    $a = { BE 88 01 ?? ?? AD 8B F8 95 }

  condition:
    $a
}