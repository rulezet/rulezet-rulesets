rule TTP_XOR_MULT_DOSStub_92d9 {
  strings:
    $key_92d9 = { c6 b1 [2] b2 a9 [2] f5 ab [2] b2 ba [2] fc b6 [2] f0 bc [2] e7 b7 [2] fc f9 [2] c1 }

  condition:
    any of them
}