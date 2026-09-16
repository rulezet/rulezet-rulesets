rule TTP_XOR_MULT_DOSStub_8164 {
  strings:
    $key_8164 = { d5 0c [2] a1 14 [2] e6 16 [2] a1 07 [2] ef 0b [2] e3 01 [2] f4 0a [2] ef 44 [2] d2 }

  condition:
    any of them
}