rule TTP_XOR_MULT_DOSStub_85b5 {
  strings:
    $key_85b5 = { d1 dd [2] a5 c5 [2] e2 c7 [2] a5 d6 [2] eb da [2] e7 d0 [2] f0 db [2] eb 95 [2] d6 }

  condition:
    any of them
}