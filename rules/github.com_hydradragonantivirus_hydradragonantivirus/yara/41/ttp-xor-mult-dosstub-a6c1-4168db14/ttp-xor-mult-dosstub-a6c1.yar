rule TTP_XOR_MULT_DOSStub_a6c1 {
  strings:
    $key_a6c1 = { f2 a9 [2] 86 b1 [2] c1 b3 [2] 86 a2 [2] c8 ae [2] c4 a4 [2] d3 af [2] c8 e1 [2] f5 }

  condition:
    any of them
}