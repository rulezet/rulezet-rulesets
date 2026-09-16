rule TTP_XOR_MULT_DOSStub_09c6 {
  strings:
    $key_09c6 = { 5d ae [2] 29 b6 [2] 6e b4 [2] 29 a5 [2] 67 a9 [2] 6b a3 [2] 7c a8 [2] 67 e6 [2] 5a }

  condition:
    any of them
}