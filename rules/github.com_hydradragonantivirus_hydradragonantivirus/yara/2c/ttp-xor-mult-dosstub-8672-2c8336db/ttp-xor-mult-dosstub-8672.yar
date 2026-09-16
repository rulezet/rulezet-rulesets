rule TTP_XOR_MULT_DOSStub_8672 {
  strings:
    $key_8672 = { d2 1a [2] a6 02 [2] e1 00 [2] a6 11 [2] e8 1d [2] e4 17 [2] f3 1c [2] e8 52 [2] d5 }

  condition:
    any of them
}