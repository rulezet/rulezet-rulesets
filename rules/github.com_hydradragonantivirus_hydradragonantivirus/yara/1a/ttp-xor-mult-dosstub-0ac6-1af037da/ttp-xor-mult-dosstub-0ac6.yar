rule TTP_XOR_MULT_DOSStub_0ac6 {
  strings:
    $key_0ac6 = { 5e ae [2] 2a b6 [2] 6d b4 [2] 2a a5 [2] 64 a9 [2] 68 a3 [2] 7f a8 [2] 64 e6 [2] 59 }

  condition:
    any of them
}