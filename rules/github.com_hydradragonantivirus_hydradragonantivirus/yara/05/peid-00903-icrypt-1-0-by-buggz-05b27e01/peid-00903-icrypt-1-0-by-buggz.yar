rule PEiD_00903_ICrypt_1_0___by_BuGGz_ {
  meta:
    description = "[ICrypt 1.0 - by BuGGz]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 83 C4 EC 53 56 57 33 C0 89 45 EC B8 70 3B 00 10 E8 3C FA FF FF 33 C0 55 68 6C 3C 00 10 64 FF 30 64 89 20 6A 0A 68 7C 3C 00 10 A1 50 56 00 10 50 E8 D8 FA FF FF 8B D8 53 A1 50 56 00 10 50 E8 0A FB FF FF 8B F8 53 A1 50 56 00 10 50 E8 D4 FA FF FF 8B }

  condition:
    $a
}