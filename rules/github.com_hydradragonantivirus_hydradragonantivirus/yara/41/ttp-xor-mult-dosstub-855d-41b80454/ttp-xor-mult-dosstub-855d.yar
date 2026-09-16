rule TTP_XOR_MULT_DOSStub_855d {
  strings:
    $key_855d = { d1 35 [2] a5 2d [2] e2 2f [2] a5 3e [2] eb 32 [2] e7 38 [2] f0 33 [2] eb 7d [2] d6 }

  condition:
    any of them
}