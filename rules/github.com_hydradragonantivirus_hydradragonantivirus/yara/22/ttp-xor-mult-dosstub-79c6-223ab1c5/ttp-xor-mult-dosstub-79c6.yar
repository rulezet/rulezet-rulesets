rule TTP_XOR_MULT_DOSStub_79c6 {
  strings:
    $key_79c6 = { 2d ae [2] 59 b6 [2] 1e b4 [2] 59 a5 [2] 17 a9 [2] 1b a3 [2] 0c a8 [2] 17 e6 [2] 2a }

  condition:
    any of them
}