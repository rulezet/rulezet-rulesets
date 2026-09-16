rule TTP_XOR_MULT_DOSStub_8147 {
  strings:
    $key_8147 = { d5 2f [2] a1 37 [2] e6 35 [2] a1 24 [2] ef 28 [2] e3 22 [2] f4 29 [2] ef 67 [2] d2 }

  condition:
    any of them
}