rule libavcodec_COOK_cvh_huffcodes6__16_lil_64_ {
  strings:
    $a0 = { 00 00 08 00 09 00 34 00 0a 00 35 00 36 00 f6 00 0b 00 37 00 38 00 f7 00 39 00 fa 01 f8 00 fc 03 0c 00 3a 00 7a 00 f9 00 3b 00 fb 01 fa 00 fe 07 3c 00 fc 01 fb 00 fd 03 fc 00 fe 03 fd 01 ff 07 }

  condition:
    $a0
}