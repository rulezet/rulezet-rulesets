rule TTP_XOR_MULT_DOSStub_a7d4 {
  strings:
    $key_a7d4 = { f3 bc [2] 87 a4 [2] c0 a6 [2] 87 b7 [2] c9 bb [2] c5 b1 [2] d2 ba [2] c9 f4 [2] f4 }

  condition:
    any of them
}