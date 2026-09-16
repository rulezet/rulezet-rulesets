rule TTP_XOR_MULT_DOSStub_a6e2 {
  strings:
    $key_a6e2 = { f2 8a [2] 86 92 [2] c1 90 [2] 86 81 [2] c8 8d [2] c4 87 [2] d3 8c [2] c8 c2 [2] f5 }

  condition:
    any of them
}