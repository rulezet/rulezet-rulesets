rule TTP_XOR_MULT_DOSStub_8372 {
  strings:
    $key_8372 = { d7 1a [2] a3 02 [2] e4 00 [2] a3 11 [2] ed 1d [2] e1 17 [2] f6 1c [2] ed 52 [2] d0 }

  condition:
    any of them
}