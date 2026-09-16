rule TTP_XOR_MULT_DOSStub_85d4 {
  strings:
    $key_85d4 = { d1 bc [2] a5 a4 [2] e2 a6 [2] a5 b7 [2] eb bb [2] e7 b1 [2] f0 ba [2] eb f4 [2] d6 }

  condition:
    any of them
}