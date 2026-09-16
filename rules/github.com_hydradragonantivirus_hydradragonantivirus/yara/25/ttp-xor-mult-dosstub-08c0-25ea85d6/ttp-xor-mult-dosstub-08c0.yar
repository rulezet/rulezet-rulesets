rule TTP_XOR_MULT_DOSStub_08c0 {
  strings:
    $key_08c0 = { 5c a8 [2] 28 b0 [2] 6f b2 [2] 28 a3 [2] 66 af [2] 6a a5 [2] 7d ae [2] 66 e0 [2] 5b }

  condition:
    any of them
}