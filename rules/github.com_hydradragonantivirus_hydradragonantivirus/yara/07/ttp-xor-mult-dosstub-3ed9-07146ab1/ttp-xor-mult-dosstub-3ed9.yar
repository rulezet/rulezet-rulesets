rule TTP_XOR_MULT_DOSStub_3ed9 {
  strings:
    $key_3ed9 = { 6a b1 [2] 1e a9 [2] 59 ab [2] 1e ba [2] 50 b6 [2] 5c bc [2] 4b b7 [2] 50 f9 [2] 6d }

  condition:
    any of them
}