rule TTP_XOR_MULT_DOSStub_8422 {
  strings:
    $key_8422 = { d0 4a [2] a4 52 [2] e3 50 [2] a4 41 [2] ea 4d [2] e6 47 [2] f1 4c [2] ea 02 [2] d7 }

  condition:
    any of them
}