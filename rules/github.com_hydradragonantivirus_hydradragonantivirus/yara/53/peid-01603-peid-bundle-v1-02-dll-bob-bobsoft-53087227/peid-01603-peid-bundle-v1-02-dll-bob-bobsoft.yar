rule PEiD_01603_PEiD_Bundle_V1_02_DLL____BoB___BobSoft_ {
  meta:
    description = "[PEiD-Bundle V1.02 DLL -> BoB / BobSoft]"
    ep_only     = "true"

  strings:
    $a = { 83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 9C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 41 00 08 00 39 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 }

  condition:
    $a
}