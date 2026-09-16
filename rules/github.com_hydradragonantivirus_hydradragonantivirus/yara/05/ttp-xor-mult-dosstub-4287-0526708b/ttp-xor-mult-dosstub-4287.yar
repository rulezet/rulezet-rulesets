rule TTP_XOR_MULT_DOSStub_4287 {
  strings:
    $key_4287 = { 16 ef [2] 62 f7 [2] 25 f5 [2] 62 e4 [2] 2c e8 [2] 20 e2 [2] 37 e9 [2] 2c a7 [2] 11 }

  condition:
    any of them
}