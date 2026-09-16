rule TTP_XOR_MULT_DOSStub_a0c1 {
  strings:
    $key_a0c1 = { f4 a9 [2] 80 b1 [2] c7 b3 [2] 80 a2 [2] ce ae [2] c2 a4 [2] d5 af [2] ce e1 [2] f3 }

  condition:
    any of them
}