rule TTP_XOR_MULT_DOSStub_86b2 {
  strings:
    $key_86b2 = { d2 da [2] a6 c2 [2] e1 c0 [2] a6 d1 [2] e8 dd [2] e4 d7 [2] f3 dc [2] e8 92 [2] d5 }

  condition:
    any of them
}