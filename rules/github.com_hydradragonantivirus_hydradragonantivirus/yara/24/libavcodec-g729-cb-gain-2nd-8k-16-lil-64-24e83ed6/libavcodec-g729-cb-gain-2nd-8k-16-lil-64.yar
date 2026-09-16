rule libavcodec_G729_cb_gain_2nd_8k__16_lil_64_ {
  strings:
    $a0 = { 16 14 50 02 93 43 45 07 10 18 5b 09 f0 3e 40 0d 3a 03 d5 07 1d 4a 2f 17 ca 07 00 00 4a 3c ed 00 4d 29 96 0b 1c 3b 32 13 31 2d ac 04 72 37 5e 06 9b 1f fd 12 39 3b c4 37 a0 23 0d 02 cc 33 b8 0c }

  condition:
    $a0
}