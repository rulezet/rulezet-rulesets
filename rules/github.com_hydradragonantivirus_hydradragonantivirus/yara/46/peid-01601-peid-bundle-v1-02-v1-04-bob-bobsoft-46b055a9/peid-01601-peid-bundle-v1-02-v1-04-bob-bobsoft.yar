rule PEiD_01601_PEiD_Bundle_v1_02___v1_04____BoB___BobSoft_ {
  meta:
    description = "[PEiD-Bundle v1.02 - v1.04 -> BoB / BobSoft]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 ?? ?? ?? 2E ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44 }

  condition:
    $a
}