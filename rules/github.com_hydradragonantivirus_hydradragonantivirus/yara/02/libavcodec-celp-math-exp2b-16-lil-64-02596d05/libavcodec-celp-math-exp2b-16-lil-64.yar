rule libavcodec_celp_math_exp2b__16_lil_64_ {
  strings:
    $a0 = { 03 00 c8 02 90 05 56 08 1d 0b e5 0d ae 10 76 13 40 16 09 19 d4 1b 9f 1e 6a 21 36 24 02 27 d0 29 9d 2c 6a 2f 39 32 08 35 d7 37 a6 3a 76 3d 47 40 18 43 ea 45 bc 48 8f 4b 62 4e 36 51 0a 54 de 56 }

  condition:
    $a0
}