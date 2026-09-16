rule TTP_XOR_MULT_DOSStub_84f9 {
  strings:
    $key_84f9 = { d0 91 [2] a4 89 [2] e3 8b [2] a4 9a [2] ea 96 [2] e6 9c [2] f1 97 [2] ea d9 [2] d7 }

  condition:
    any of them
}