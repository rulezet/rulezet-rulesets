rule PEiD_02294_Turbo_C_or_Borland_C___ {
  meta:
    description = "[Turbo C or Borland C++]"
    ep_only     = "true"

  strings:
    $a = { BA ?? ?? 2E 89 16 ?? ?? B4 30 CD 21 8B 2E ?? ?? 8B 1E ?? ?? 8E DA }

  condition:
    $a
}