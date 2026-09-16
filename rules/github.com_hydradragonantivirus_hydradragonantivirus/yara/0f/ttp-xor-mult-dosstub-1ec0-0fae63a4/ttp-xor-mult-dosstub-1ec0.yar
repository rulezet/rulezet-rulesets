rule TTP_XOR_MULT_DOSStub_1ec0 {
  strings:
    $key_1ec0 = { 4a a8 [2] 3e b0 [2] 79 b2 [2] 3e a3 [2] 70 af [2] 7c a5 [2] 6b ae [2] 70 e0 [2] 4d }

  condition:
    any of them
}