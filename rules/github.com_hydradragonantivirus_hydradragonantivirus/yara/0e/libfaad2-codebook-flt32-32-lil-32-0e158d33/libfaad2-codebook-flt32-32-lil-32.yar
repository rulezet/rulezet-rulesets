rule libfaad2_codebook__flt32___32_lil_32_ {
  strings:
    $a0 = { d9 21 12 3f 6d 55 32 3f 08 21 50 3f 38 4b 69 3f 68 22 7c 3f c0 b0 88 3f b0 e8 98 3f db 4c af 3f }

  condition:
    $a0
}