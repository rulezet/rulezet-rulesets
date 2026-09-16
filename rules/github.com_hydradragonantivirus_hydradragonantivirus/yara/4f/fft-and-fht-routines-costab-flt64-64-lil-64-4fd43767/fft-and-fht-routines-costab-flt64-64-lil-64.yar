rule FFT_and_FHT_routines_costab__flt64___64_lil_64_ {
  strings:
    $a0 = { 46 8d 32 cf 6b 90 ed 3f 63 a9 ae a6 e2 7d d8 3f 26 25 d1 a3 8d d8 ef 3f 2c b4 29 bc a6 17 b9 3f 0d cd 84 60 88 fd ef 3f 7f 66 a3 f7 55 21 99 3f 92 8a 8e 85 d8 ff ef 3f 71 00 67 fe f0 21 79 3f }

  condition:
    $a0
}