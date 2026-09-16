rule libavcodec_imc_weights1__flt32___32_lil_124_ {
  strings:
    $a0 = { 39 ee f4 3d 70 28 fc 3d e8 4a 04 3e 47 43 cc 3d 3f c7 a7 3d 19 d8 c4 3d 75 ca b3 3d 52 5e b0 3d 2a 80 b8 3d 70 17 cb 3d d3 67 e7 3d e5 45 06 3e 26 8e 1c 3e 09 8c 35 3e d2 1a 63 3e 86 cb 7a 3e d1 e6 88 3e fd 16 9d 3e 49 66 a5 3e 46 b1 ac 3e ac c9 bb 3e 3b fd c8 3e 9e d0 cb 3e 9a 7d ce 3e 60 59 d9 3e d0 b9 e3 3e f8 fb e5 3e 16 30 e9 3e 26 a9 f4 3e d8 2b 00 3f 3f a9 02 3f }

  condition:
    $a0
}