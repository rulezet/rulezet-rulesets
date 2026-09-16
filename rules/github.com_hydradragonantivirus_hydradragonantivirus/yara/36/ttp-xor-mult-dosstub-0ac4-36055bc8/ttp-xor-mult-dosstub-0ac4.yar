rule TTP_XOR_MULT_DOSStub_0ac4 {
  strings:
    $key_0ac4 = { 5e ac [2] 2a b4 [2] 6d b6 [2] 2a a7 [2] 64 ab [2] 68 a1 [2] 7f aa [2] 64 e4 [2] 59 }

  condition:
    any of them
}