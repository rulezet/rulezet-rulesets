rule Lucifer__smith__s0__8_byt_16_ {
  strings:
    $a0 = { 0c 0f 07 0a 0e 0d 0b 00 02 06 03 01 09 04 05 08 }

  condition:
    $a0
}