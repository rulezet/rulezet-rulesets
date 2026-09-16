rule TTP_XOR_MULT_DOSStub_8363 {
  strings:
    $key_8363 = { d7 0b [2] a3 13 [2] e4 11 [2] a3 00 [2] ed 0c [2] e1 06 [2] f6 0d [2] ed 43 [2] d0 }

  condition:
    any of them
}