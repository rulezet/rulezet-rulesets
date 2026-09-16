rule TTP_XOR_MULT_DOSStub_8100 {
  strings:
    $key_8100 = { d5 68 [2] a1 70 [2] e6 72 [2] a1 63 [2] ef 6f [2] e3 65 [2] f4 6e [2] ef 20 [2] d2 }

  condition:
    any of them
}