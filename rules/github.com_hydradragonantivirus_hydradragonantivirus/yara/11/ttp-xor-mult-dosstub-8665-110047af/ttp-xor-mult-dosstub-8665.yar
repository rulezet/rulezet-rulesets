rule TTP_XOR_MULT_DOSStub_8665 {
  strings:
    $key_8665 = { d2 0d [2] a6 15 [2] e1 17 [2] a6 06 [2] e8 0a [2] e4 00 [2] f3 0b [2] e8 45 [2] d5 }

  condition:
    any of them
}