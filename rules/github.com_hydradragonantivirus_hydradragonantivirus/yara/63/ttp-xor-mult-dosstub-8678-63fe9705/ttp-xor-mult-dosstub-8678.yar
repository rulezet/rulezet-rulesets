rule TTP_XOR_MULT_DOSStub_8678 {
  strings:
    $key_8678 = { d2 10 [2] a6 08 [2] e1 0a [2] a6 1b [2] e8 17 [2] e4 1d [2] f3 16 [2] e8 58 [2] d5 }

  condition:
    any of them
}