rule TTP_XOR_MULT_DOSStub_a640 {
  strings:
    $key_a640 = { f2 28 [2] 86 30 [2] c1 32 [2] 86 23 [2] c8 2f [2] c4 25 [2] d3 2e [2] c8 60 [2] f5 }

  condition:
    any of them
}