rule TTP_XOR_MULT_DOSStub_78c4 {
  strings:
    $key_78c4 = { 2c ac [2] 58 b4 [2] 1f b6 [2] 58 a7 [2] 16 ab [2] 1a a1 [2] 0d aa [2] 16 e4 [2] 2b }

  condition:
    any of them
}