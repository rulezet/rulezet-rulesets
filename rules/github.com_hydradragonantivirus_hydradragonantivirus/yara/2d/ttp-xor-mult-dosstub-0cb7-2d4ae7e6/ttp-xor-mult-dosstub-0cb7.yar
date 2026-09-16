rule TTP_XOR_MULT_DOSStub_0cb7 {
  strings:
    $key_0cb7 = { 58 df [2] 2c c7 [2] 6b c5 [2] 2c d4 [2] 62 d8 [2] 6e d2 [2] 79 d9 [2] 62 97 [2] 5f }

  condition:
    any of them
}