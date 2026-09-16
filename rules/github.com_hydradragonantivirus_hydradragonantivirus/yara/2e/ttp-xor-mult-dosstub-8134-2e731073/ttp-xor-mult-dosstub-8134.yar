rule TTP_XOR_MULT_DOSStub_8134 {
  strings:
    $key_8134 = { d5 5c [2] a1 44 [2] e6 46 [2] a1 57 [2] ef 5b [2] e3 51 [2] f4 5a [2] ef 14 [2] d2 }

  condition:
    any of them
}