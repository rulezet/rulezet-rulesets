rule TTP_XOR_MULT_DOSStub_8146 {
  strings:
    $key_8146 = { d5 2e [2] a1 36 [2] e6 34 [2] a1 25 [2] ef 29 [2] e3 23 [2] f4 28 [2] ef 66 [2] d2 }

  condition:
    any of them
}