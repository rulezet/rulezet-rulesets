rule Crypton_v1_p0__8_byt_16_ {
  strings:
    $a0 = { 0f 0e 0a 01 0b 05 08 0d 09 03 02 07 00 06 04 0c }

  condition:
    $a0
}