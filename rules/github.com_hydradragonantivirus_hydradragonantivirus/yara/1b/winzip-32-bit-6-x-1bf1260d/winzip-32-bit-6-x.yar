import "pe"
rule WinZip__32_bit__6_x {
  strings:
    $a0 = { FF 15 FC 81 40 00 B1 22 38 08 74 02 B1 20 40 80 38 00 74 10 }

  condition:
    $a0 at pe.entry_point
}