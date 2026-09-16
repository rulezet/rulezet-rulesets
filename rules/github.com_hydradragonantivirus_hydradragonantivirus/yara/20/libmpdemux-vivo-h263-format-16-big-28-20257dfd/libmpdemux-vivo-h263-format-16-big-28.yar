rule libmpdemux_vivo_h263_format__16_big_28_ {
  strings:
    $a0 = { 00 00 00 00 00 80 00 60 00 b0 00 90 01 60 01 20 02 c0 02 40 05 80 04 80 01 40 00 f0 }

  condition:
    $a0
}