rule TTP_XOR_MULT_DOSStub_a635 {
  strings:
    $key_a635 = { f2 5d [2] 86 45 [2] c1 47 [2] 86 56 [2] c8 5a [2] c4 50 [2] d3 5b [2] c8 15 [2] f5 }

  condition:
    any of them
}