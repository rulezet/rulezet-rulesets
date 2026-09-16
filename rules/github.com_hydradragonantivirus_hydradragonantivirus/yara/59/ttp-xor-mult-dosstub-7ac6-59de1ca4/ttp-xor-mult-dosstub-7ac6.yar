rule TTP_XOR_MULT_DOSStub_7ac6 {
  strings:
    $key_7ac6 = { 2e ae [2] 5a b6 [2] 1d b4 [2] 5a a5 [2] 14 a9 [2] 18 a3 [2] 0f a8 [2] 14 e6 [2] 29 }

  condition:
    any of them
}