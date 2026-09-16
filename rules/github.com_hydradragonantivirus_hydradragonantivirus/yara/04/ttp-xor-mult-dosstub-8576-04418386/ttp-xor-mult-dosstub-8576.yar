rule TTP_XOR_MULT_DOSStub_8576 {
  strings:
    $key_8576 = { d1 1e [2] a5 06 [2] e2 04 [2] a5 15 [2] eb 19 [2] e7 13 [2] f0 18 [2] eb 56 [2] d6 }

  condition:
    any of them
}