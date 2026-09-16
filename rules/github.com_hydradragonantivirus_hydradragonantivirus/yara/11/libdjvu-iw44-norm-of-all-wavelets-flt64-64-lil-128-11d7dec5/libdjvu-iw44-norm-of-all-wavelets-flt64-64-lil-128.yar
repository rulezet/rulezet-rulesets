rule libdjvu_IW44_norm_of_all_wavelets__flt64___64_lil_128_ {
  strings:
    $a0 = { 7d 3f 35 5e fa 87 a4 40 73 d7 12 f2 41 e9 66 40 5d dc 46 03 78 e9 66 40 26 e4 83 9e cd 92 49 40 d1 96 73 29 ae ea 46 40 34 4b 02 d4 d4 ea 46 40 12 83 c0 ca a1 95 29 40 3c 31 eb c5 50 fe 26 40 03 60 3c 83 86 fe 26 40 11 e5 0b 5a 48 c0 09 40 08 1d 74 09 87 fe 07 40 5d 18 e9 45 ed fe 07 40 9e 3f 12 9b 34 f2 eb 3f d1 78 22 88 f3 30 f1 3f 7b 13 43 72 32 31 f1 3f f0 b8 4d 5d 9e 73 db 3f }

  condition:
    $a0
}