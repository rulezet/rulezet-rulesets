rule TTP_XOR_MULT_DOSStub_42c0 {
  strings:
    $key_42c0 = { 16 a8 [2] 62 b0 [2] 25 b2 [2] 62 a3 [2] 2c af [2] 20 a5 [2] 37 ae [2] 2c e0 [2] 11 }

  condition:
    any of them
}