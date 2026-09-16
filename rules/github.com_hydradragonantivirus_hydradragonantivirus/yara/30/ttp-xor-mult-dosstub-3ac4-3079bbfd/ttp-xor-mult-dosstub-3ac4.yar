rule TTP_XOR_MULT_DOSStub_3ac4 {
  strings:
    $key_3ac4 = { 6e ac [2] 1a b4 [2] 5d b6 [2] 1a a7 [2] 54 ab [2] 58 a1 [2] 4f aa [2] 54 e4 [2] 69 }

  condition:
    any of them
}