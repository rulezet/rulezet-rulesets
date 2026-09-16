rule TTP_XOR_MULT_DOSStub_95c3 {
  strings:
    $key_95c3 = { c1 ab [2] b5 b3 [2] f2 b1 [2] b5 a0 [2] fb ac [2] f7 a6 [2] e0 ad [2] fb e3 [2] c6 }

  condition:
    any of them
}