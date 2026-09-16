rule TTP_XOR_MULT_DOSStub_92d5 {
  strings:
    $key_92d5 = { c6 bd [2] b2 a5 [2] f5 a7 [2] b2 b6 [2] fc ba [2] f0 b0 [2] e7 bb [2] fc f5 [2] c1 }

  condition:
    any of them
}