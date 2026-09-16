rule TTP_XOR_MULT_DOSStub_a67d {
  strings:
    $key_a67d = { f2 15 [2] 86 0d [2] c1 0f [2] 86 1e [2] c8 12 [2] c4 18 [2] d3 13 [2] c8 5d [2] f5 }

  condition:
    any of them
}