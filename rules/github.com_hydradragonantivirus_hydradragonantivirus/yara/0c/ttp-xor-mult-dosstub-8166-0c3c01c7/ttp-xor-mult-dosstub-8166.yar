rule TTP_XOR_MULT_DOSStub_8166 {
  strings:
    $key_8166 = { d5 0e [2] a1 16 [2] e6 14 [2] a1 05 [2] ef 09 [2] e3 03 [2] f4 08 [2] ef 46 [2] d2 }

  condition:
    any of them
}