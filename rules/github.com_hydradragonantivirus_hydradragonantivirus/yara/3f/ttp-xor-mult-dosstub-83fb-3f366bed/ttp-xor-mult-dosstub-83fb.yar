rule TTP_XOR_MULT_DOSStub_83fb {
  strings:
    $key_83fb = { d7 93 [2] a3 8b [2] e4 89 [2] a3 98 [2] ed 94 [2] e1 9e [2] f6 95 [2] ed db [2] d0 }

  condition:
    any of them
}