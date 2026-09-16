rule TTP_XOR_MULT_DOSStub_a6e4 {
  strings:
    $key_a6e4 = { f2 8c [2] 86 94 [2] c1 96 [2] 86 87 [2] c8 8b [2] c4 81 [2] d3 8a [2] c8 c4 [2] f5 }

  condition:
    any of them
}