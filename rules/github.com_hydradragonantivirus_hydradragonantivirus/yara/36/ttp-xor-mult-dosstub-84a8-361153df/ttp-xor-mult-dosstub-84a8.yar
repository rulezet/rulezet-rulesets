rule TTP_XOR_MULT_DOSStub_84a8 {
  strings:
    $key_84a8 = { d0 c0 [2] a4 d8 [2] e3 da [2] a4 cb [2] ea c7 [2] e6 cd [2] f1 c6 [2] ea 88 [2] d7 }

  condition:
    any of them
}