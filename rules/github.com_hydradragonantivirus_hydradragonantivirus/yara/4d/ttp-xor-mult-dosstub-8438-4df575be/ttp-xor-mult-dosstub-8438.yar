rule TTP_XOR_MULT_DOSStub_8438 {
  strings:
    $key_8438 = { d0 50 [2] a4 48 [2] e3 4a [2] a4 5b [2] ea 57 [2] e6 5d [2] f1 56 [2] ea 18 [2] d7 }

  condition:
    any of them
}