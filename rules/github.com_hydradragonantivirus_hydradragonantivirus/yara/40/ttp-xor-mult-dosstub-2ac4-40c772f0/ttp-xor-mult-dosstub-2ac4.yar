rule TTP_XOR_MULT_DOSStub_2ac4 {
  strings:
    $key_2ac4 = { 7e ac [2] 0a b4 [2] 4d b6 [2] 0a a7 [2] 44 ab [2] 48 a1 [2] 5f aa [2] 44 e4 [2] 79 }

  condition:
    any of them
}