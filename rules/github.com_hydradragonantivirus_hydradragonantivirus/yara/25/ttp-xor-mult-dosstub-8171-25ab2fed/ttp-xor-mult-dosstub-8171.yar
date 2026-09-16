rule TTP_XOR_MULT_DOSStub_8171 {
  strings:
    $key_8171 = { d5 19 [2] a1 01 [2] e6 03 [2] a1 12 [2] ef 1e [2] e3 14 [2] f4 1f [2] ef 51 [2] d2 }

  condition:
    any of them
}