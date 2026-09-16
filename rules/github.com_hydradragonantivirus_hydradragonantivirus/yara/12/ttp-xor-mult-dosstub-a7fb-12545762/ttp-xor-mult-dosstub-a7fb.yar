rule TTP_XOR_MULT_DOSStub_a7fb {
  strings:
    $key_a7fb = { f3 93 [2] 87 8b [2] c0 89 [2] 87 98 [2] c9 94 [2] c5 9e [2] d2 95 [2] c9 db [2] f4 }

  condition:
    any of them
}