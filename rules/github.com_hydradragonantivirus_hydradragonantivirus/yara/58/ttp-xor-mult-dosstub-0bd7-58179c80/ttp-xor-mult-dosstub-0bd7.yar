rule TTP_XOR_MULT_DOSStub_0bd7 {
  strings:
    $key_0bd7 = { 5f bf [2] 2b a7 [2] 6c a5 [2] 2b b4 [2] 65 b8 [2] 69 b2 [2] 7e b9 [2] 65 f7 [2] 58 }

  condition:
    any of them
}