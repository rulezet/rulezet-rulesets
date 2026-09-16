rule TTP_XOR_MULT_DOSStub_8542 {
  strings:
    $key_8542 = { d1 2a [2] a5 32 [2] e2 30 [2] a5 21 [2] eb 2d [2] e7 27 [2] f0 2c [2] eb 62 [2] d6 }

  condition:
    any of them
}