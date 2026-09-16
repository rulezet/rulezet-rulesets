rule TTP_XOR_MULT_DOSStub_84f2 {
  strings:
    $key_84f2 = { d0 9a [2] a4 82 [2] e3 80 [2] a4 91 [2] ea 9d [2] e6 97 [2] f1 9c [2] ea d2 [2] d7 }

  condition:
    any of them
}