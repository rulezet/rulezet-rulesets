rule TTP_XOR_MULT_DOSStub_a187 {
  strings:
    $key_a187 = { f5 ef [2] 81 f7 [2] c6 f5 [2] 81 e4 [2] cf e8 [2] c3 e2 [2] d4 e9 [2] cf a7 [2] f2 }

  condition:
    any of them
}