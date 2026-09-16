rule TTP_XOR_MULT_DOSStub_81f6 {
  strings:
    $key_81f6 = { d5 9e [2] a1 86 [2] e6 84 [2] a1 95 [2] ef 99 [2] e3 93 [2] f4 98 [2] ef d6 [2] d2 }

  condition:
    any of them
}