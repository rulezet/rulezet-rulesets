rule TTP_XOR_MULT_DOSStub_a676 {
  strings:
    $key_a676 = { f2 1e [2] 86 06 [2] c1 04 [2] 86 15 [2] c8 19 [2] c4 13 [2] d3 18 [2] c8 56 [2] f5 }

  condition:
    any of them
}