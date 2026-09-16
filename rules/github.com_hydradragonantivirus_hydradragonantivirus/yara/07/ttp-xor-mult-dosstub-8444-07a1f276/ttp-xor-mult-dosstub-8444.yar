rule TTP_XOR_MULT_DOSStub_8444 {
  strings:
    $key_8444 = { d0 2c [2] a4 34 [2] e3 36 [2] a4 27 [2] ea 2b [2] e6 21 [2] f1 2a [2] ea 64 [2] d7 }

  condition:
    any of them
}