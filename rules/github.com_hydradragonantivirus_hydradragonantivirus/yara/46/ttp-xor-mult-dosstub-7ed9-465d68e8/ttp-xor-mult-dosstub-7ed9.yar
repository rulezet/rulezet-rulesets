rule TTP_XOR_MULT_DOSStub_7ed9 {
  strings:
    $key_7ed9 = { 2a b1 [2] 5e a9 [2] 19 ab [2] 5e ba [2] 10 b6 [2] 1c bc [2] 0b b7 [2] 10 f9 [2] 2d }

  condition:
    any of them
}