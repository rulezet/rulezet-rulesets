rule libmpdemux_tivo_Series1AudioWithPTS__32_lil_24_ {
  strings:
    $a0 = { 5b 01 00 00 8b 01 00 00 eb 01 00 00 4b 02 00 00 0b 03 00 00 6b 03 00 00 }

  condition:
    $a0
}