rule TTP_XOR_MULT_DOSStub_85b2 {
  strings:
    $key_85b2 = { d1 da [2] a5 c2 [2] e2 c0 [2] a5 d1 [2] eb dd [2] e7 d7 [2] f0 dc [2] eb 92 [2] d6 }

  condition:
    any of them
}