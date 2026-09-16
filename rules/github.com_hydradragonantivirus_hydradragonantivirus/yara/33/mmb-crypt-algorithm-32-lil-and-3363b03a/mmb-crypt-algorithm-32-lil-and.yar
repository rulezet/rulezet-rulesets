rule MMB_crypt_algorithm__32_lil_AND_ {
  strings:
    $a0 = { db 1c 5f 02 [0-20] b6 39 be 04 [0-20] d8 e6 f8 12 [0-20] 81 6d 8e 2f [0-20] 94 46 ad 0d [0-20] 4a a3 d6 06 [0-20] d2 a8 b5 81 [0-20] 8d 5a 1b 28 [0-20] aa aa aa 2a }

  condition:
    $a0
}