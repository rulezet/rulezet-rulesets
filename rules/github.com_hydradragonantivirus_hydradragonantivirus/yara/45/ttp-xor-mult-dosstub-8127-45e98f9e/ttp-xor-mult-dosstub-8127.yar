rule TTP_XOR_MULT_DOSStub_8127 {
  strings:
    $key_8127 = { d5 4f [2] a1 57 [2] e6 55 [2] a1 44 [2] ef 48 [2] e3 42 [2] f4 49 [2] ef 07 [2] d2 }

  condition:
    any of them
}