rule TTP_XOR_MULT_DOSStub_a1c8 {
  strings:
    $key_a1c8 = { f5 a0 [2] 81 b8 [2] c6 ba [2] 81 ab [2] cf a7 [2] c3 ad [2] d4 a6 [2] cf e8 [2] f2 }

  condition:
    any of them
}