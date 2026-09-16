rule TTP_XOR_MULT_DOSStub_42c6 {
  strings:
    $key_42c6 = { 16 ae [2] 62 b6 [2] 25 b4 [2] 62 a5 [2] 2c a9 [2] 20 a3 [2] 37 a8 [2] 2c e6 [2] 11 }

  condition:
    any of them
}