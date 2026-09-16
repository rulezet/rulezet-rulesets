rule TTP_XOR_MULT_DOSStub_1ed9 {
  strings:
    $key_1ed9 = { 4a b1 [2] 3e a9 [2] 79 ab [2] 3e ba [2] 70 b6 [2] 7c bc [2] 6b b7 [2] 70 f9 [2] 4d }

  condition:
    any of them
}