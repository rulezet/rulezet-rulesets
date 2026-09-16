rule TTP_XOR_MULT_DOSStub_86d4 {
  strings:
    $key_86d4 = { d2 bc [2] a6 a4 [2] e1 a6 [2] a6 b7 [2] e8 bb [2] e4 b1 [2] f3 ba [2] e8 f4 [2] d5 }

  condition:
    any of them
}