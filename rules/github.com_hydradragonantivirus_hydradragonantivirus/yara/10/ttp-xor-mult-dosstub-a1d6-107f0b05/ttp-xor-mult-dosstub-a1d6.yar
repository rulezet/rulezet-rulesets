rule TTP_XOR_MULT_DOSStub_a1d6 {
  strings:
    $key_a1d6 = { f5 be [2] 81 a6 [2] c6 a4 [2] 81 b5 [2] cf b9 [2] c3 b3 [2] d4 b8 [2] cf f6 [2] f2 }

  condition:
    any of them
}