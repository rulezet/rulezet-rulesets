rule TTP_XOR_MULT_DOSStub_8572 {
  strings:
    $key_8572 = { d1 1a [2] a5 02 [2] e2 00 [2] a5 11 [2] eb 1d [2] e7 17 [2] f0 1c [2] eb 52 [2] d6 }

  condition:
    any of them
}