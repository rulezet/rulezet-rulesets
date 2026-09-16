rule TTP_XOR_MULT_DOSStub_85a9 {
  strings:
    $key_85a9 = { d1 c1 [2] a5 d9 [2] e2 db [2] a5 ca [2] eb c6 [2] e7 cc [2] f0 c7 [2] eb 89 [2] d6 }

  condition:
    any of them
}