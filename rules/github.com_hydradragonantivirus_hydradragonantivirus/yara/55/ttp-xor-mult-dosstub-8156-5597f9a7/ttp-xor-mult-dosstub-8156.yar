rule TTP_XOR_MULT_DOSStub_8156 {
  strings:
    $key_8156 = { d5 3e [2] a1 26 [2] e6 24 [2] a1 35 [2] ef 39 [2] e3 33 [2] f4 38 [2] ef 76 [2] d2 }

  condition:
    any of them
}