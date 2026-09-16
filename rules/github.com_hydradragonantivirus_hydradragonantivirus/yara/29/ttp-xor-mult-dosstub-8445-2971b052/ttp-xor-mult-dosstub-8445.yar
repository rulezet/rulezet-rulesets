rule TTP_XOR_MULT_DOSStub_8445 {
  strings:
    $key_8445 = { d0 2d [2] a4 35 [2] e3 37 [2] a4 26 [2] ea 2a [2] e6 20 [2] f1 2b [2] ea 65 [2] d7 }

  condition:
    any of them
}