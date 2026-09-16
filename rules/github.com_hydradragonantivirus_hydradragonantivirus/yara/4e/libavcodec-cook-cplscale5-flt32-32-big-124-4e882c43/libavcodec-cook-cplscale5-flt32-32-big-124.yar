rule libavcodec_COOK_cplscale5__flt32___32_big_124_ {
  strings:
    $a0 = { 3f 7e f5 08 3f 7c cd f4 3f 7a 8d d1 3f 78 31 87 3f 75 b5 4f 3f 73 14 7b 3f 70 49 27 3f 6d 4b b0 3f 6a 11 f0 3f 66 8d e9 3f 62 ab 57 3f 5e 4a ff 3f 59 38 02 3f 53 0a af 3f 4a b5 98 3f 35 04 f3 3f 1c 59 45 3f 10 e7 9e 3f 07 78 35 3e fd f1 91 3e ed f7 74 3e de 89 85 3e cf 56 60 3e c0 1c b9 3e b0 9f 05 3e a0 99 a9 3e 8f b6 eb 3e 7a f3 49 3e 52 17 f6 3e 21 4a 01 3d b8 ab 0e }

  condition:
    $a0
}