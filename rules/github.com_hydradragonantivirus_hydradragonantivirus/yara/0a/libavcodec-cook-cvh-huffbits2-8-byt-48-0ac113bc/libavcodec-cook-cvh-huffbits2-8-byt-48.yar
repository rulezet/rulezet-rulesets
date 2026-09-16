rule libavcodec_COOK_cvh_huffbits2__8_byt_48_ {
  strings:
    $a0 = { 01 04 05 07 08 09 0a 03 04 05 07 08 09 0a 05 05 06 07 08 0a 0a 07 06 07 08 09 0a 0c 08 08 08 09 0a 0c 0e 08 09 09 0a 0b 0f 10 09 0a 0b 0c 0d 10 }

  condition:
    $a0
}