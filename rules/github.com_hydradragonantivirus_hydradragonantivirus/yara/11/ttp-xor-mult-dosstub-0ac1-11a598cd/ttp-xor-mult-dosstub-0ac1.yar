rule TTP_XOR_MULT_DOSStub_0ac1 {
  strings:
    $key_0ac1 = { 5e a9 [2] 2a b1 [2] 6d b3 [2] 2a a2 [2] 64 ae [2] 68 a4 [2] 7f af [2] 64 e1 [2] 59 }

  condition:
    any of them
}