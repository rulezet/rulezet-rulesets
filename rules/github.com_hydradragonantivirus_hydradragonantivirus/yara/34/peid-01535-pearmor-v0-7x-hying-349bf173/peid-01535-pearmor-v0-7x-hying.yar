rule PEiD_01535_PEArmor_V0_7X____Hying_ {
  meta:
    description = "[PEArmor V0.7X -> Hying]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 8D B5 ?? ?? ?? ?? 55 56 81 C5 ?? ?? ?? ?? 55 C3 }

  condition:
    $a
}