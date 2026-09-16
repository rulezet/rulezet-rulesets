rule libavcodec_huffyuv_classic_shift_luma__8_byt_43_ {
  strings:
    $a0 = { 22 24 23 45 87 e8 09 10 0a 18 0b 17 0c 10 0d 0a 0e 08 0f 08 10 08 11 14 10 0a cf ce cd ec 0b 08 0a 15 09 17 08 08 c7 46 45 44 00 }

  condition:
    $a0
}