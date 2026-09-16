rule TTP_XOR_MULT_DOSStub_42c5 {
  strings:
    $key_42c5 = { 16 ad [2] 62 b5 [2] 25 b7 [2] 62 a6 [2] 2c aa [2] 20 a0 [2] 37 ab [2] 2c e5 [2] 11 }

  condition:
    any of them
}