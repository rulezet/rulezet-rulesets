rule TTP_XOR_MULT_DOSStub_81f0 {
  strings:
    $key_81f0 = { d5 98 [2] a1 80 [2] e6 82 [2] a1 93 [2] ef 9f [2] e3 95 [2] f4 9e [2] ef d0 [2] d2 }

  condition:
    any of them
}