rule TTP_XOR_MULT_DOSStub_81f1 {
  strings:
    $key_81f1 = { d5 99 [2] a1 81 [2] e6 83 [2] a1 92 [2] ef 9e [2] e3 94 [2] f4 9f [2] ef d1 [2] d2 }

  condition:
    any of them
}