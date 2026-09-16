rule TTP_XOR_MULT_DOSStub_8668 {
  strings:
    $key_8668 = { d2 00 [2] a6 18 [2] e1 1a [2] a6 0b [2] e8 07 [2] e4 0d [2] f3 06 [2] e8 48 [2] d5 }

  condition:
    any of them
}