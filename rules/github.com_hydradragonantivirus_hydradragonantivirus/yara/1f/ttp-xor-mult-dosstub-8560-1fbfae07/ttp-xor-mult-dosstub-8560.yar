rule TTP_XOR_MULT_DOSStub_8560 {
  strings:
    $key_8560 = { d1 08 [2] a5 10 [2] e2 12 [2] a5 03 [2] eb 0f [2] e7 05 [2] f0 0e [2] eb 40 [2] d6 }

  condition:
    any of them
}