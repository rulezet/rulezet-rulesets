rule TTP_XOR_MULT_DOSStub_a1c7 {
  strings:
    $key_a1c7 = { f5 af [2] 81 b7 [2] c6 b5 [2] 81 a4 [2] cf a8 [2] c3 a2 [2] d4 a9 [2] cf e7 [2] f2 }

  condition:
    any of them
}