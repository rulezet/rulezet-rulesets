rule TTP_XOR_MULT_DOSStub_a1c1 {
  strings:
    $key_a1c1 = { f5 a9 [2] 81 b1 [2] c6 b3 [2] 81 a2 [2] cf ae [2] c3 a4 [2] d4 af [2] cf e1 [2] f2 }

  condition:
    any of them
}