rule TTP_XOR_MULT_DOSStub_a3fb {
  strings:
    $key_a3fb = { f7 93 [2] 83 8b [2] c4 89 [2] 83 98 [2] cd 94 [2] c1 9e [2] d6 95 [2] cd db [2] f0 }

  condition:
    any of them
}