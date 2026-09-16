rule TTP_XOR_MULT_DOSStub_8142 {
  strings:
    $key_8142 = { d5 2a [2] a1 32 [2] e6 30 [2] a1 21 [2] ef 2d [2] e3 27 [2] f4 2c [2] ef 62 [2] d2 }

  condition:
    any of them
}