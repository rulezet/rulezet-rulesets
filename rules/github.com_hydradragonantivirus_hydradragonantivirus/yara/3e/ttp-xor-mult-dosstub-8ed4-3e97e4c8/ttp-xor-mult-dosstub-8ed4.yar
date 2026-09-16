rule TTP_XOR_MULT_DOSStub_8ed4 {
  strings:
    $key_8ed4 = { da bc [2] ae a4 [2] e9 a6 [2] ae b7 [2] e0 bb [2] ec b1 [2] fb ba [2] e0 f4 [2] dd }

  condition:
    any of them
}