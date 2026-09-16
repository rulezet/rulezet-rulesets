rule TTP_XOR_MULT_DOSStub_a657 {
  strings:
    $key_a657 = { f2 3f [2] 86 27 [2] c1 25 [2] 86 34 [2] c8 38 [2] c4 32 [2] d3 39 [2] c8 77 [2] f5 }

  condition:
    any of them
}