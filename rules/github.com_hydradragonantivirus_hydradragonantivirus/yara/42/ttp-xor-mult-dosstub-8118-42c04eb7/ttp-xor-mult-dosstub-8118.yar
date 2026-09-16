rule TTP_XOR_MULT_DOSStub_8118 {
  strings:
    $key_8118 = { d5 70 [2] a1 68 [2] e6 6a [2] a1 7b [2] ef 77 [2] e3 7d [2] f4 76 [2] ef 38 [2] d2 }

  condition:
    any of them
}