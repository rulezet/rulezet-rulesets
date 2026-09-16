rule TTP_XOR_MULT_DOSStub_84e6 {
  strings:
    $key_84e6 = { d0 8e [2] a4 96 [2] e3 94 [2] a4 85 [2] ea 89 [2] e6 83 [2] f1 88 [2] ea c6 [2] d7 }

  condition:
    any of them
}