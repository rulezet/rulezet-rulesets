rule TTP_XOR_MULT_DOSStub_a65b {
  strings:
    $key_a65b = { f2 33 [2] 86 2b [2] c1 29 [2] 86 38 [2] c8 34 [2] c4 3e [2] d3 35 [2] c8 7b [2] f5 }

  condition:
    any of them
}