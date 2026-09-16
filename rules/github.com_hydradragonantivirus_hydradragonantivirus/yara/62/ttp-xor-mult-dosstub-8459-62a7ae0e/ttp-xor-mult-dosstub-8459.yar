rule TTP_XOR_MULT_DOSStub_8459 {
  strings:
    $key_8459 = { d0 31 [2] a4 29 [2] e3 2b [2] a4 3a [2] ea 36 [2] e6 3c [2] f1 37 [2] ea 79 [2] d7 }

  condition:
    any of them
}