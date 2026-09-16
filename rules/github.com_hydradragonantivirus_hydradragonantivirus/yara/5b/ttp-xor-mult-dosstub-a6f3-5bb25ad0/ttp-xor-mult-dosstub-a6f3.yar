rule TTP_XOR_MULT_DOSStub_a6f3 {
  strings:
    $key_a6f3 = { f2 9b [2] 86 83 [2] c1 81 [2] 86 90 [2] c8 9c [2] c4 96 [2] d3 9d [2] c8 d3 [2] f5 }

  condition:
    any of them
}