rule CRC_5_USB_poly_0x14__8_byt_refl_False_ {
  strings:
    $a0 = { 00 14 28 3c 50 44 78 6c a0 b4 88 9c f0 e4 d8 cc 54 40 7c 68 04 10 2c 38 f4 e0 dc c8 a4 b0 8c 98 a8 bc 80 94 f8 ec d0 c4 08 1c 20 34 58 4c 70 64 fc e8 d4 c0 ac b8 84 90 5c 48 74 60 0c 18 24 30 44 50 6c 78 14 00 3c 28 e4 f0 cc d8 b4 a0 9c 88 10 04 38 2c 40 54 68 7c b0 a4 98 8c e0 f4 c8 dc ec f8 c4 d0 bc a8 94 80 4c 58 64 70 1c 08 34 20 b8 ac 90 84 e8 fc c0 d4 18 0c 30 24 48 5c 60 74 88 9c a0 b4 d8 cc f0 e4 28 3c 00 14 78 6c 50 44 dc c8 f4 e0 8c 98 a4 b0 7c 68 54 40 2c 38 04 10 20 34 08 1c 70 64 58 4c 80 94 a8 bc d0 c4 f8 ec 74 60 5c 48 24 30 0c 18 d4 c0 fc e8 84 90 ac b8 cc d8 e4 f0 9c 88 b4 a0 6c 78 44 50 3c 28 14 00 98 8c b0 a4 c8 dc e0 f4 38 2c 10 04 68 7c 40 54 64 70 4c 58 34 20 1c 08 c4 d0 ec f8 94 80 bc a8 30 24 18 0c 60 74 48 5c 90 84 b8 ac c0 d4 e8 fc }

  condition:
    $a0
}