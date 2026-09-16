rule PEiD_00874_Hardlock_dongle__Alladin__ {
  meta:
    description = "[Hardlock dongle (Alladin)]"
    ep_only     = "true"

  strings:
    $a = { 5C 5C 2E 5C 48 41 52 44 4C 4F 43 4B 2E 56 58 44 00 00 00 00 5C 5C 2E 5C 46 45 6E 74 65 44 65 76 }

  condition:
    $a
}