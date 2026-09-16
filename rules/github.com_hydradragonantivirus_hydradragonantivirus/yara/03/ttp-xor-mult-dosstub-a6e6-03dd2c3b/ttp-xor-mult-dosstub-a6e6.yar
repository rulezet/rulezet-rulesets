rule TTP_XOR_MULT_DOSStub_a6e6 {
  strings:
    $key_a6e6 = { f2 8e [2] 86 96 [2] c1 94 [2] 86 85 [2] c8 89 [2] c4 83 [2] d3 88 [2] c8 c6 [2] f5 }

  condition:
    any of them
}