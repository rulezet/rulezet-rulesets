rule TTP_XOR_MULT_DOSStub_a6fb {
  strings:
    $key_a6fb = { f2 93 [2] 86 8b [2] c1 89 [2] 86 98 [2] c8 94 [2] c4 9e [2] d3 95 [2] c8 db [2] f5 }

  condition:
    any of them
}