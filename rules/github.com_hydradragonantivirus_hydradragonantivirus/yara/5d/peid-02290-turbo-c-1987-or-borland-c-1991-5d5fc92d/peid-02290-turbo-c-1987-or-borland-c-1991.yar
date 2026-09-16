rule PEiD_02290_Turbo_C_1987_or_Borland_C___1991_ {
  meta:
    description = "[Turbo C 1987 or Borland C++ 1991]"
    ep_only     = "true"

  strings:
    $a = { FB BA ?? ?? 2E 89 ?? ?? ?? B4 30 CD 21 }

  condition:
    $a
}