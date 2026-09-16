rule TTP_XOR_MULT_DOSStub_3ec6 {
  strings:
    $key_3ec6 = { 6a ae [2] 1e b6 [2] 59 b4 [2] 1e a5 [2] 50 a9 [2] 5c a3 [2] 4b a8 [2] 50 e6 [2] 6d }

  condition:
    any of them
}