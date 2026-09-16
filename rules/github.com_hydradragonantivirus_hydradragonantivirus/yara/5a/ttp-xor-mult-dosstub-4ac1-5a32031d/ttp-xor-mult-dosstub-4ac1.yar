rule TTP_XOR_MULT_DOSStub_4ac1 {
  strings:
    $key_4ac1 = { 1e a9 [2] 6a b1 [2] 2d b3 [2] 6a a2 [2] 24 ae [2] 28 a4 [2] 3f af [2] 24 e1 [2] 19 }

  condition:
    any of them
}