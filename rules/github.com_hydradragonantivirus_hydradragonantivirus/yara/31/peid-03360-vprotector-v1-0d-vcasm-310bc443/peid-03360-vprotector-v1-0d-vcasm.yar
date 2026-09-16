rule PEiD_03360_VProtector_V1_0D____vcasm_ {
  meta:
    description = "[VProtector V1.0D -> vcasm]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 6A FF 68 CA 31 41 00 68 06 32 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 }

  condition:
    $a
}