rule TTP_XOR_MULT_DOSStub_853d {
  strings:
    $key_853d = { d1 55 [2] a5 4d [2] e2 4f [2] a5 5e [2] eb 52 [2] e7 58 [2] f0 53 [2] eb 1d [2] d6 }

  condition:
    any of them
}