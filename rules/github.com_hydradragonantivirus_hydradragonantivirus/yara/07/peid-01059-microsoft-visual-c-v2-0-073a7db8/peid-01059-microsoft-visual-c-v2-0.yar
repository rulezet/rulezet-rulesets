rule PEiD_01059_Microsoft_Visual_C_v2_0_ {
  meta:
    description = "[Microsoft Visual C v2.0]"
    ep_only     = "true"

  strings:
    $a = { 53 56 57 BB ?? ?? ?? ?? 8B ?? ?? ?? 55 3B FB 75 }

  condition:
    $a
}