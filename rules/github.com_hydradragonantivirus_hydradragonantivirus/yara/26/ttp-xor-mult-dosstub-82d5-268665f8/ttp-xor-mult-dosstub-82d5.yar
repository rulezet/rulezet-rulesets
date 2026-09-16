rule TTP_XOR_MULT_DOSStub_82d5 {
  strings:
    $key_82d5 = { d6 bd [2] a2 a5 [2] e5 a7 [2] a2 b6 [2] ec ba [2] e0 b0 [2] f7 bb [2] ec f5 [2] d1 }

  condition:
    any of them
}