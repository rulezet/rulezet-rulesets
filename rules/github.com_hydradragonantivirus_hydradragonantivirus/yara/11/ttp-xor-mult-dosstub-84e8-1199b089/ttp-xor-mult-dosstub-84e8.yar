rule TTP_XOR_MULT_DOSStub_84e8 {
  strings:
    $key_84e8 = { d0 80 [2] a4 98 [2] e3 9a [2] a4 8b [2] ea 87 [2] e6 8d [2] f1 86 [2] ea c8 [2] d7 }

  condition:
    any of them
}