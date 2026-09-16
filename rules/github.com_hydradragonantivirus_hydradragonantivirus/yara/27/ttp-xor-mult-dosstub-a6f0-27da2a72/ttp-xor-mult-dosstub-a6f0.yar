rule TTP_XOR_MULT_DOSStub_a6f0 {
  strings:
    $key_a6f0 = { f2 98 [2] 86 80 [2] c1 82 [2] 86 93 [2] c8 9f [2] c4 95 [2] d3 9e [2] c8 d0 [2] f5 }

  condition:
    any of them
}