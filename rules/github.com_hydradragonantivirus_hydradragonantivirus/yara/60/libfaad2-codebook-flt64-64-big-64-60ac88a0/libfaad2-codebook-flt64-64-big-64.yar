rule libfaad2_codebook__flt64___64_big_64_ {
  strings:
    $a0 = { 3f e2 44 3b 2d d3 77 e2 3f e6 4a ad a3 3b d9 cb 3f ea 04 20 f6 f0 8c c5 3f ed 29 67 01 96 d8 f5 3f ef 84 4d 01 3a 92 a3 3f f1 16 18 04 d9 83 94 3f f3 1d 15 f0 2c 4d 66 3f f5 e9 9b 6f 5c af 2d }

  condition:
    $a0
}