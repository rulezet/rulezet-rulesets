rule TTP_XOR_MULT_DOSStub_a7c7 {
  strings:
    $key_a7c7 = { f3 af [2] 87 b7 [2] c0 b5 [2] 87 a4 [2] c9 a8 [2] c5 a2 [2] d2 a9 [2] c9 e7 [2] f4 }

  condition:
    any of them
}