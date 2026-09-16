rule TTP_XOR_MULT_DOSStub_8176 {
  strings:
    $key_8176 = { d5 1e [2] a1 06 [2] e6 04 [2] a1 15 [2] ef 19 [2] e3 13 [2] f4 18 [2] ef 56 [2] d2 }

  condition:
    any of them
}