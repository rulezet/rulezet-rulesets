rule TTP_XOR_MULT_DOSStub_19c6 {
  strings:
    $key_19c6 = { 4d ae [2] 39 b6 [2] 7e b4 [2] 39 a5 [2] 77 a9 [2] 7b a3 [2] 6c a8 [2] 77 e6 [2] 4a }

  condition:
    any of them
}