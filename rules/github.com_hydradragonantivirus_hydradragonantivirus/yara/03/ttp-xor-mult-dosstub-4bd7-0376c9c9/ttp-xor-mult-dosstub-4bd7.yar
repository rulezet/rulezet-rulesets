rule TTP_XOR_MULT_DOSStub_4bd7 {
  strings:
    $key_4bd7 = { 1f bf [2] 6b a7 [2] 2c a5 [2] 6b b4 [2] 25 b8 [2] 29 b2 [2] 3e b9 [2] 25 f7 [2] 18 }

  condition:
    any of them
}