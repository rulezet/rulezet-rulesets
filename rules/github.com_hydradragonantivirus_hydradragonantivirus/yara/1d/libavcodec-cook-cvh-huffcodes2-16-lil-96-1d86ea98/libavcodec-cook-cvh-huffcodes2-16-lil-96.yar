rule libavcodec_COOK_cvh_huffcodes2__16_lil_96_ {
  strings:
    $a0 = { 00 00 0a 00 18 00 74 00 f2 00 f4 01 f6 03 04 00 0b 00 19 00 75 00 f3 00 f5 01 f7 03 1a 00 1b 00 38 00 76 00 f4 00 f8 03 f9 03 77 00 39 00 78 00 f5 00 f6 01 fa 03 fc 0f f6 00 f7 00 f8 00 f7 01 fb 03 fd 0f fe 3f f9 00 f8 01 f9 01 fc 03 fc 07 fe 7f fe ff fa 01 fd 03 fd 07 fe 0f fe 1f ff ff }

  condition:
    $a0
}