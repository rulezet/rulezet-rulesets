rule TTP_XOR_MULT_DOSStub_85d0 {
  strings:
    $key_85d0 = { d1 b8 [2] a5 a0 [2] e2 a2 [2] a5 b3 [2] eb bf [2] e7 b5 [2] f0 be [2] eb f0 [2] d6 }

  condition:
    any of them
}