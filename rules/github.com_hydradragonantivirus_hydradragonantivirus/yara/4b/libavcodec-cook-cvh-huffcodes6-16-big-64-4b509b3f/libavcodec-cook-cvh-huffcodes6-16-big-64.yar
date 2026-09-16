rule libavcodec_COOK_cvh_huffcodes6__16_big_64_ {
  strings:
    $a0 = { 00 00 00 08 00 09 00 34 00 0a 00 35 00 36 00 f6 00 0b 00 37 00 38 00 f7 00 39 01 fa 00 f8 03 fc 00 0c 00 3a 00 7a 00 f9 00 3b 01 fb 00 fa 07 fe 00 3c 01 fc 00 fb 03 fd 00 fc 03 fe 01 fd 07 ff }

  condition:
    $a0
}