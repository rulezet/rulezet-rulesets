rule TTP_XOR_MULT_DOSStub_3ac6 {
  strings:
    $key_3ac6 = { 6e ae [2] 1a b6 [2] 5d b4 [2] 1a a5 [2] 54 a9 [2] 58 a3 [2] 4f a8 [2] 54 e6 [2] 69 }

  condition:
    any of them
}