rule PEiD_00674_eXPressor_1_4_5_1____CGSoftLabs_ {
  meta:
    description = "[eXPressor 1.4.5.1 -> CGSoftLabs]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 83 EC 58 53 56 57 83 65 DC 00 F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 34 2E 00 A1 00 ?? ?? 00 05 00 ?? ?? 00 A3 08 ?? ?? 00 A1 08 ?? ?? 00 B9 81 ?? ?? 00 2B 48 18 89 0D 0C ?? ?? 00 83 3D 10 ?? ?? 00 00 74 16 A1 08 ?? ?? 00 8B 0D 0C ?? ?? 00 03 48 14 }

  condition:
    $a
}