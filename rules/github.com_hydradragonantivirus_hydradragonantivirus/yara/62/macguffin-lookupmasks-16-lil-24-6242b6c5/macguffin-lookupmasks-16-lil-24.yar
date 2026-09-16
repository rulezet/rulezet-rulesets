rule MacGuffin_lookupmasks__16_lil_24_ {
  strings:
    $a0 = { 36 00 c0 06 00 69 48 50 06 21 11 84 01 86 28 48 c4 10 80 29 11 90 2a 02 }

  condition:
    $a0
}