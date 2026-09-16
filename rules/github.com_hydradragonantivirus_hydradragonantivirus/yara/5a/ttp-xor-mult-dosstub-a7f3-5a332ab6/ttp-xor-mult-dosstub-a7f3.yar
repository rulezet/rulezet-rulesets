rule TTP_XOR_MULT_DOSStub_a7f3 {
  strings:
    $key_a7f3 = { f3 9b [2] 87 83 [2] c0 81 [2] 87 90 [2] c9 9c [2] c5 96 [2] d2 9d [2] c9 d3 [2] f4 }

  condition:
    any of them
}