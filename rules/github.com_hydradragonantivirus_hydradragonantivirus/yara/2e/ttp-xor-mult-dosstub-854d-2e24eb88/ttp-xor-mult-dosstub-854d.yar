rule TTP_XOR_MULT_DOSStub_854d {
  strings:
    $key_854d = { d1 25 [2] a5 3d [2] e2 3f [2] a5 2e [2] eb 22 [2] e7 28 [2] f0 23 [2] eb 6d [2] d6 }

  condition:
    any of them
}