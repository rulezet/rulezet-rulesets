rule TTP_XOR_MULT_DOSStub_8563 {
  strings:
    $key_8563 = { d1 0b [2] a5 13 [2] e2 11 [2] a5 00 [2] eb 0c [2] e7 06 [2] f0 0d [2] eb 43 [2] d6 }

  condition:
    any of them
}