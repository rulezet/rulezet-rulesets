rule TTP_XOR_MULT_DOSStub_8368 {
  strings:
    $key_8368 = { d7 00 [2] a3 18 [2] e4 1a [2] a3 0b [2] ed 07 [2] e1 0d [2] f6 06 [2] ed 48 [2] d0 }

  condition:
    any of them
}