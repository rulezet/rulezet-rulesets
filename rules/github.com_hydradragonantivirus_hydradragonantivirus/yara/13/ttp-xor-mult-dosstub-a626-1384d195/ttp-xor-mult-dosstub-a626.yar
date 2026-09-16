rule TTP_XOR_MULT_DOSStub_a626 {
  strings:
    $key_a626 = { f2 4e [2] 86 56 [2] c1 54 [2] 86 45 [2] c8 49 [2] c4 43 [2] d3 48 [2] c8 06 [2] f5 }

  condition:
    any of them
}