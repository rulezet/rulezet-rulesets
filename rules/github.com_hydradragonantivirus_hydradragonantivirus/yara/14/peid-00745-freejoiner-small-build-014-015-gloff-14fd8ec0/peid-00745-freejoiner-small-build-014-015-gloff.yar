rule PEiD_00745_FreeJoiner_Small__build_014_015_____GlOFF_ {
  meta:
    description = "[FreeJoiner Small (build 014/015) -> GlOFF]"
    ep_only     = "false"

  strings:
    $a = { 55 8B EC 83 C4 F0 86 FF 68 00 01 00 00 68 F8 13 40 00 6A 00 E8 F3 01 00 00 8A C0 6A 00 68 80 00 00 00 6A 03 6A 00 6A 00 68 00 00 00 80 68 F8 13 40 00 E8 C9 01 00 00 A3 E0 13 40 00 40 0F 84 8B 01 00 00 90 90 90 90 90 6A 02 6A 00 6A FB FF 35 E0 13 40 00 E8 D1 01 00 00 86 FF 6A 00 8D 45 FC 50 6A 04 8D 45 F8 50 FF 35 E0 13 40 00 E8 B2 01 00 00 8A C0 6A 00 8D 45 FC 50 6A 01 8D 45 F3 50 }

  condition:
    $a
}