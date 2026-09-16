rule TTP_XOR_MULT_DOSStub_94a9 {
  strings:
    $key_94a9 = { c0 c1 [2] b4 d9 [2] f3 db [2] b4 ca [2] fa c6 [2] f6 cc [2] e1 c7 [2] fa 89 [2] c7 }

  condition:
    any of them
}