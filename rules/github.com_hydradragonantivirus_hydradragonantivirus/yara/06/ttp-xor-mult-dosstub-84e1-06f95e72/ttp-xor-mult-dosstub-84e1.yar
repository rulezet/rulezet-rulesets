rule TTP_XOR_MULT_DOSStub_84e1 {
  strings:
    $key_84e1 = { d0 89 [2] a4 91 [2] e3 93 [2] a4 82 [2] ea 8e [2] e6 84 [2] f1 8f [2] ea c1 [2] d7 }

  condition:
    any of them
}