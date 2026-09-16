rule Jpeg_dct_AA_N_scale_factor__flt64___64_big_64_ {
  strings:
    $a0 = { 3f f0 00 00 00 00 00 00 3f f6 31 50 b1 48 61 ef 3f f4 e7 ae 91 4d 6f ca 3f f2 d0 62 ef 6c 11 aa 3f f0 00 00 00 00 00 00 3f e9 24 69 c0 a7 bf 3b 3f e1 51 7a 7b c7 20 bb 3f d1 a8 55 de 72 ab 5d }

  condition:
    $a0
}