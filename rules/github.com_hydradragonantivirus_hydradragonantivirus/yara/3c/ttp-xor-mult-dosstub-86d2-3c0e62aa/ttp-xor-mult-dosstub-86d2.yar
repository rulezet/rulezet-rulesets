rule TTP_XOR_MULT_DOSStub_86d2 {
  strings:
    $key_86d2 = { d2 ba [2] a6 a2 [2] e1 a0 [2] a6 b1 [2] e8 bd [2] e4 b7 [2] f3 bc [2] e8 f2 [2] d5 }

  condition:
    any of them
}