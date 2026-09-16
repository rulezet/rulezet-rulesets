rule libavcodec_COOK_cvh_huffbits4__8_byt_246_ {
  strings:
    $a0 = { 02 04 07 0a 04 05 07 0a 07 08 0a 0e 0b 0b 0f 0f 04 05 09 0c 05 05 08 0c 08 07 0a 0f 0b 0b 0f 0f 07 09 0c 0f 08 08 0c 0f 0a 0a 0d 0f 0e 0e 0f 00 0b 0d 0f 0f 0b 0d 0f 0f 0e 0f 0f 00 0f 0f 00 00 04 05 09 0d 05 06 09 0d 09 09 0b 0f 0e 0d 0f 0f 04 06 09 0c 05 06 09 0d 09 08 0b 0f 0d 0c 0f 0f 07 09 0c 0f 07 08 0b 0f 0a 0a 0e 0f 0e 0f 0f 00 0a 0c 0f 0f 0b 0d 0f 0f 0f 0f 0f 00 0f 0f 00 00 06 09 0d 0e 08 09 0c 0f 0c 0c 0f 0f 0f 0f 0f 00 07 09 0d 0f 08 09 0c 0f 0b 0c 0f 0f 0f 0f 0f 00 09 0b 0f 0f 09 0b 0f 0f 0e 0e 0f 00 0f 0f 00 00 0e 0f 0f 00 0e 0f 0f 00 0f 0f 00 00 00 00 00 00 09 0c 0f 0f 0c 0d 0f 0f 0f 0f 0f 00 0f 0f 00 00 0a 0c 0f 0f 0c 0e 0f 0f 0f 0f 0f 00 0f 0f 00 00 0e 0f 0f 00 0f 0f 0f 00 0f 0f 00 00 00 00 00 00 0f 0f 00 00 0f 0f }

  condition:
    $a0
}