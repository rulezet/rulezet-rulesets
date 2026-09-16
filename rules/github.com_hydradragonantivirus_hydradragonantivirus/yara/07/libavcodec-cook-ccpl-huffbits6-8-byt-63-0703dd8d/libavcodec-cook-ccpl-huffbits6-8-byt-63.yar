rule libavcodec_COOK_ccpl_huffbits6__8_byt_63_ {
  strings:
    $a0 = { 10 0f 0e 0d 0c 0b 0b 0b 0b 0a 0a 0a 0a 09 09 09 09 09 08 08 08 08 07 07 07 07 06 06 05 05 03 01 04 05 05 06 06 07 07 07 07 08 08 08 08 09 09 09 09 0a 0a 0a 0a 0a 0b 0b 0b 0b 0c 0d 0e 0e 10 }

  condition:
    $a0
}