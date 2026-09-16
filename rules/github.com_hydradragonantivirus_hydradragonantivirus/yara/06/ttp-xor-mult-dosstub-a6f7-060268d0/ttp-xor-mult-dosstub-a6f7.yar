rule TTP_XOR_MULT_DOSStub_a6f7 {
  strings:
    $key_a6f7 = { f2 9f [2] 86 87 [2] c1 85 [2] 86 94 [2] c8 98 [2] c4 92 [2] d3 99 [2] c8 d7 [2] f5 }

  condition:
    any of them
}