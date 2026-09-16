rule TTP_XOR_MULT_DOSStub_5ac6 {
  strings:
    $key_5ac6 = { 0e ae [2] 7a b6 [2] 3d b4 [2] 7a a5 [2] 34 a9 [2] 38 a3 [2] 2f a8 [2] 34 e6 [2] 09 }

  condition:
    any of them
}