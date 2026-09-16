rule TTP_XOR_MULT_DOSStub_97d4 {
  strings:
    $key_97d4 = { c3 bc [2] b7 a4 [2] f0 a6 [2] b7 b7 [2] f9 bb [2] f5 b1 [2] e2 ba [2] f9 f4 [2] c4 }

  condition:
    any of them
}