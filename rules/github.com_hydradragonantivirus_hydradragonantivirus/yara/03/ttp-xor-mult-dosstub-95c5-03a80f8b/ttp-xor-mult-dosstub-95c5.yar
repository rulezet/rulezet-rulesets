rule TTP_XOR_MULT_DOSStub_95c5 {
  strings:
    $key_95c5 = { c1 ad [2] b5 b5 [2] f2 b7 [2] b5 a6 [2] fb aa [2] f7 a0 [2] e0 ab [2] fb e5 [2] c6 }

  condition:
    any of them
}