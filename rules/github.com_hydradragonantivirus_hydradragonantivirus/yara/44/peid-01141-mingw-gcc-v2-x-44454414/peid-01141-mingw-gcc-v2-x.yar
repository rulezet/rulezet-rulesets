rule PEiD_01141_MinGW_GCC_v2_x_ {
  meta:
    description = "[MinGW GCC v2.x]"
    ep_only     = "true"

  strings:
    $a = { 55 89 E5 E8 ?? ?? ?? ?? C9 C3 ?? ?? 45 58 45 }

  condition:
    $a
}