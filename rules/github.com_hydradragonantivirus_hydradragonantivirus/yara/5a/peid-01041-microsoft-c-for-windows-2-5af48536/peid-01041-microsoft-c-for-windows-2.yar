rule PEiD_01041_Microsoft_C_for_Windows__2__ {
  meta:
    description = "[Microsoft C for Windows (2)]"
    ep_only     = "true"

  strings:
    $a = { 8C D8 ?? 45 55 8B EC 1E 8E D8 57 56 89 }

  condition:
    $a
}