rule TTP_XOR_MULT_DOSStub_8165 {
  strings:
    $key_8165 = { d5 0d [2] a1 15 [2] e6 17 [2] a1 06 [2] ef 0a [2] e3 00 [2] f4 0b [2] ef 45 [2] d2 }

  condition:
    any of them
}