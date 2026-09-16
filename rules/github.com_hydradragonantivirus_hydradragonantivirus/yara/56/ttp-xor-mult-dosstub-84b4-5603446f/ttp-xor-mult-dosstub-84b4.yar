rule TTP_XOR_MULT_DOSStub_84b4 {
  strings:
    $key_84b4 = { d0 dc [2] a4 c4 [2] e3 c6 [2] a4 d7 [2] ea db [2] e6 d1 [2] f1 da [2] ea 94 [2] d7 }

  condition:
    any of them
}