rule TTP_XOR_MULT_DOSStub_85b3 {
  strings:
    $key_85b3 = { d1 db [2] a5 c3 [2] e2 c1 [2] a5 d0 [2] eb dc [2] e7 d6 [2] f0 dd [2] eb 93 [2] d6 }

  condition:
    any of them
}