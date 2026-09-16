rule TTP_XOR_MULT_DOSStub_84a9 {
  strings:
    $key_84a9 = { d0 c1 [2] a4 d9 [2] e3 db [2] a4 ca [2] ea c6 [2] e6 cc [2] f1 c7 [2] ea 89 [2] d7 }

  condition:
    any of them
}