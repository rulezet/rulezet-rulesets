rule TTP_XOR_MULT_DOSStub_08c1 {
  strings:
    $key_08c1 = { 5c a9 [2] 28 b1 [2] 6f b3 [2] 28 a2 [2] 66 ae [2] 6a a4 [2] 7d af [2] 66 e1 [2] 5b }

  condition:
    any of them
}