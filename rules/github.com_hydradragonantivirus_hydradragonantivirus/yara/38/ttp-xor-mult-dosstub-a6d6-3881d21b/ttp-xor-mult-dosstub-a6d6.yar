rule TTP_XOR_MULT_DOSStub_a6d6 {
  strings:
    $key_a6d6 = { f2 be [2] 86 a6 [2] c1 a4 [2] 86 b5 [2] c8 b9 [2] c4 b3 [2] d3 b8 [2] c8 f6 [2] f5 }

  condition:
    any of them
}