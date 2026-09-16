rule TTP_XOR_MULT_DOSStub_85fb {
  strings:
    $key_85fb = { d1 93 [2] a5 8b [2] e2 89 [2] a5 98 [2] eb 94 [2] e7 9e [2] f0 95 [2] eb db [2] d6 }

  condition:
    any of them
}