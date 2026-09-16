rule YUV_to_RGB_dither_8x8_220__8_byt_64_ {
  strings:
    $a0 = { 75 3e 9e 67 71 3a 9b 64 22 c7 15 ba 1f c4 11 b6 90 59 83 4c 8d 56 7f 48 00 a5 29 ce 0a af 34 d9 6e 37 97 60 78 41 a2 6b 1c c1 0e b3 26 cb 18 bd 8a 53 7c 45 94 5d 86 4f 07 ac 30 d5 03 a8 2d d2 }

  condition:
    $a0
}