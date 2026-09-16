rule TTP_XOR_MULT_DOSStub_8527 {
  strings:
    $key_8527 = { d1 4f [2] a5 57 [2] e2 55 [2] a5 44 [2] eb 48 [2] e7 42 [2] f0 49 [2] eb 07 [2] d6 }

  condition:
    any of them
}