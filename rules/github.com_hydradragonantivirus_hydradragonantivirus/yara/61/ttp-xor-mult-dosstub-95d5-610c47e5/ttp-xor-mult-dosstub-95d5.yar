rule TTP_XOR_MULT_DOSStub_95d5 {
  strings:
    $key_95d5 = { c1 bd [2] b5 a5 [2] f2 a7 [2] b5 b6 [2] fb ba [2] f7 b0 [2] e0 bb [2] fb f5 [2] c6 }

  condition:
    any of them
}