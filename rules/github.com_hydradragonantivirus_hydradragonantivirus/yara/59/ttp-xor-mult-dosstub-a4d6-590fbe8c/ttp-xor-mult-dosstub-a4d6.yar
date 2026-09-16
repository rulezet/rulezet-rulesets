rule TTP_XOR_MULT_DOSStub_a4d6 {
  strings:
    $key_a4d6 = { f0 be [2] 84 a6 [2] c3 a4 [2] 84 b5 [2] ca b9 [2] c6 b3 [2] d1 b8 [2] ca f6 [2] f7 }

  condition:
    any of them
}