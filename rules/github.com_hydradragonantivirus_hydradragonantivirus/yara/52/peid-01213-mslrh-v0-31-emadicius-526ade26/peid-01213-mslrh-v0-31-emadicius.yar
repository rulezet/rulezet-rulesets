rule PEiD_01213_MSLRH_V0_31____emadicius_ {
  meta:
    description = "[MSLRH V0.31 -> emadicius]"
    ep_only     = "true"

  strings:
    $a = { 60 D1 CB 0F CA C1 CA E0 D1 CA 0F C8 EB 01 F1 }

  condition:
    $a
}