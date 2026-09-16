rule TTP_XOR_MULT_DOSStub_92d4 {
  strings:
    $key_92d4 = { c6 bc [2] b2 a4 [2] f5 a6 [2] b2 b7 [2] fc bb [2] f0 b1 [2] e7 ba [2] fc f4 [2] c1 }

  condition:
    any of them
}