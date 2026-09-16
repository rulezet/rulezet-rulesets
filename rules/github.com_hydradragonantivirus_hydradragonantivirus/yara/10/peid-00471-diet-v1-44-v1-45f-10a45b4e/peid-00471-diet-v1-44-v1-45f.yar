rule PEiD_00471_DIET_v1_44__v1_45f_ {
  meta:
    description = "[DIET v1.44, v1.45f]"
    ep_only     = "true"

  strings:
    $a = { F8 9C 06 1E 57 56 52 51 53 50 0E FC 8C C8 BA ?? ?? 03 D0 52 }

  condition:
    $a
}