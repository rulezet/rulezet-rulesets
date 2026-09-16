rule libavcodec_imc_weights2__flt32___32_lil_124_ {
  strings:
    $a0 = { 97 fc 53 3b 21 4d 65 3b 4e 8d 82 3b 59 d6 01 3b 2b a7 98 3a 64 fd ea 3a 07 fd b7 3a 55 af ae 3a 23 4b c5 3a 9e ac ff 3a 14 d8 35 3b a8 e5 87 3b 53 b4 cd 3b 81 6b 19 3c 8e 68 8c 3c 1c 8b b7 3c 09 a1 e8 3c b8 a0 28 3d f2 ce 41 3d 8d c1 59 3d c6 85 88 3d 3e 02 a4 3d 29 4f aa 3d 03 6a b0 3d 17 98 ca 3d 8a c7 e5 3d 22 fc eb 3d a9 f7 f4 3d 32 71 0b 3e 24 28 1e 3e e6 96 26 3e }

  condition:
    $a0
}