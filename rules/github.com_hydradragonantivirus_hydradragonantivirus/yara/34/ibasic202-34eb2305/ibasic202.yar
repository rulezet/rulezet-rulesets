rule ibasic202 {
  meta:
    author      = "PEiD"
    description = "IBasic 2.02B -> Pyxia Development"
    group       = "12"
    function    = "0"

  strings:
    $a0 = { 55 8B EC 6A FF 68 D0 10 46 00 68 58 9F 43 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 C4 A8 53 56 57 89 65 E8 FF 15 D8 2B 47 00 33 D2 8A D4 89 15 C4 FD 46 00 8B C8 81 E1 FF 00 00 00 89 0D C0 FD 46 00 C1 E1 08 03 CA 89 0D BC FD 46 00 C1 E8 10 A3 B8 FD 46 00 E8 54 25 00 00 85 C0 }

  condition:
    $a0
}