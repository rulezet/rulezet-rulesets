rule TTP_XOR_MULT_DOSStub_84e2 {
  strings:
    $key_84e2 = { d0 8a [2] a4 92 [2] e3 90 [2] a4 81 [2] ea 8d [2] e6 87 [2] f1 8c [2] ea c2 [2] d7 }

  condition:
    any of them
}