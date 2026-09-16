rule TTP_XOR_MULT_DOSStub_39c6 {
  strings:
    $key_39c6 = { 6d ae [2] 19 b6 [2] 5e b4 [2] 19 a5 [2] 57 a9 [2] 5b a3 [2] 4c a8 [2] 57 e6 [2] 6a }

  condition:
    any of them
}