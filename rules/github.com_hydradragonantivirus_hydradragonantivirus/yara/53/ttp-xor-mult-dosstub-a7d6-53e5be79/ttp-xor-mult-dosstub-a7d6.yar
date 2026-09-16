rule TTP_XOR_MULT_DOSStub_a7d6 {
  strings:
    $key_a7d6 = { f3 be [2] 87 a6 [2] c0 a4 [2] 87 b5 [2] c9 b9 [2] c5 b3 [2] d2 b8 [2] c9 f6 [2] f4 }

  condition:
    any of them
}