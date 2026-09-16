rule TTP_XOR_MULT_DOSStub_8ed2 {
  strings:
    $key_8ed2 = { da ba [2] ae a2 [2] e9 a0 [2] ae b1 [2] e0 bd [2] ec b7 [2] fb bc [2] e0 f2 [2] dd }

  condition:
    any of them
}