rule TTP_XOR_MULT_DOSStub_84e7 {
  strings:
    $key_84e7 = { d0 8f [2] a4 97 [2] e3 95 [2] a4 84 [2] ea 88 [2] e6 82 [2] f1 89 [2] ea c7 [2] d7 }

  condition:
    any of them
}