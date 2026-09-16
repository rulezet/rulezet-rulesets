rule TTP_XOR_MULT_DOSStub_a7d5 {
  strings:
    $key_a7d5 = { f3 bd [2] 87 a5 [2] c0 a7 [2] 87 b6 [2] c9 ba [2] c5 b0 [2] d2 bb [2] c9 f5 [2] f4 }

  condition:
    any of them
}