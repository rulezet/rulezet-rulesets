rule TTP_XOR_MULT_DOSStub_2ec0 {
  strings:
    $key_2ec0 = { 7a a8 [2] 0e b0 [2] 49 b2 [2] 0e a3 [2] 40 af [2] 4c a5 [2] 5b ae [2] 40 e0 [2] 7d }

  condition:
    any of them
}