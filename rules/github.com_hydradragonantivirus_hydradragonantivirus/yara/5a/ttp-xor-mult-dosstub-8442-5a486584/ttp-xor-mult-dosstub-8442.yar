rule TTP_XOR_MULT_DOSStub_8442 {
  strings:
    $key_8442 = { d0 2a [2] a4 32 [2] e3 30 [2] a4 21 [2] ea 2d [2] e6 27 [2] f1 2c [2] ea 62 [2] d7 }

  condition:
    any of them
}