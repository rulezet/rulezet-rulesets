rule TTP_XOR_MULT_DOSStub_8149 {
  strings:
    $key_8149 = { d5 21 [2] a1 39 [2] e6 3b [2] a1 2a [2] ef 26 [2] e3 2c [2] f4 27 [2] ef 69 [2] d2 }

  condition:
    any of them
}