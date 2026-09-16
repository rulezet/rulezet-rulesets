rule TTP_XOR_MULT_DOSStub_84a6 {
  strings:
    $key_84a6 = { d0 ce [2] a4 d6 [2] e3 d4 [2] a4 c5 [2] ea c9 [2] e6 c3 [2] f1 c8 [2] ea 86 [2] d7 }

  condition:
    any of them
}