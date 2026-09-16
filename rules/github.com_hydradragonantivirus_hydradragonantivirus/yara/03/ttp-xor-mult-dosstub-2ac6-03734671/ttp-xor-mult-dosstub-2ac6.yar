rule TTP_XOR_MULT_DOSStub_2ac6 {
  strings:
    $key_2ac6 = { 7e ae [2] 0a b6 [2] 4d b4 [2] 0a a5 [2] 44 a9 [2] 48 a3 [2] 5f a8 [2] 44 e6 [2] 79 }

  condition:
    any of them
}