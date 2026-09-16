rule libfaad2_codebook__flt32___32_big_32_ {
  strings:
    $a0 = { 3f 12 21 d9 3f 32 55 6d 3f 50 21 08 3f 69 4b 38 3f 7c 22 68 3f 88 b0 c0 3f 98 e8 b0 3f af 4c db }

  condition:
    $a0
}