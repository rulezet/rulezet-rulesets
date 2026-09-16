rule TTP_XOR_MULT_DOSStub_1ac1 {
  strings:
    $key_1ac1 = { 4e a9 [2] 3a b1 [2] 7d b3 [2] 3a a2 [2] 74 ae [2] 78 a4 [2] 6f af [2] 74 e1 [2] 49 }

  condition:
    any of them
}