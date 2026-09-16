rule libavcodec_AAN_ff_inv_aanscales__16_big_128_ {
  strings:
    $a0 = { 10 00 0b 89 0c 3f 0d 9b 10 00 14 5d 1d 90 39 fe 0b 89 08 51 08 d4 09 cf 0b 89 0e af 15 51 29 cf 0c 3f 08 d4 09 5f 0a 6a 0c 3f 0f 96 16 a1 2c 63 0d 9b 09 cf 0a 6a 0b 92 0d 9b 11 51 19 24 31 51 10 00 0b 89 0c 3f 0d 9b 10 00 14 5d 1d 90 39 fe 14 5d 0e af 0f 96 11 51 14 5d 19 eb 25 a1 49 cf 1d 90 15 51 16 a1 19 24 1d 90 25 a1 36 a1 6b 28 39 fe 29 cf 2c 63 31 51 39 fe 49 cf 6b 28 d2 31 }

  condition:
    $a0
}