rule libavcodec_COOK_cvh_huffbits1__8_byt_97_ {
  strings:
    $a0 = { 01 04 05 06 07 08 08 09 0a 0a 04 05 06 07 07 08 08 09 09 0b 05 05 06 07 08 08 09 09 0a 0b 06 06 07 08 08 09 09 0a 0b 0c 07 07 08 08 09 09 0a 0b 0b 0d 08 08 08 09 09 0a 0a 0b 0c 0e 08 08 08 09 0a 0b 0b 0c 0d 0f 09 09 09 0a 0b 0c 0c 0e 0e 00 09 09 09 0a 0b 0c 0e 10 00 00 0a 0a 0b 0c 0d 0e 10 }

  condition:
    $a0
}