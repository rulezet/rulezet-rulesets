rule TTP_XOR_MULT_DOSStub_a7c1 {
  strings:
    $key_a7c1 = { f3 a9 [2] 87 b1 [2] c0 b3 [2] 87 a2 [2] c9 ae [2] c5 a4 [2] d2 af [2] c9 e1 [2] f4 }

  condition:
    any of them
}