rule TTP_XOR_MULT_DOSStub_8454 {
  strings:
    $key_8454 = { d0 3c [2] a4 24 [2] e3 26 [2] a4 37 [2] ea 3b [2] e6 31 [2] f1 3a [2] ea 74 [2] d7 }

  condition:
    any of them
}