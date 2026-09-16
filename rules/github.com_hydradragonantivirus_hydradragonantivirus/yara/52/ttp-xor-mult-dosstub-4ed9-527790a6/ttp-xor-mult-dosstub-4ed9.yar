rule TTP_XOR_MULT_DOSStub_4ed9 {
  strings:
    $key_4ed9 = { 1a b1 [2] 6e a9 [2] 29 ab [2] 6e ba [2] 20 b6 [2] 2c bc [2] 3b b7 [2] 20 f9 [2] 1d }

  condition:
    any of them
}