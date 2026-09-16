import "pe"
rule JDPack_2_x____JDPack {
  strings:
    $a0 = { 55 8B EC 6A FF 68 68 51 40 00 68 04 25 40 00 64 A1 00 00 00 00 }

  condition:
    $a0 at pe.entry_point
}