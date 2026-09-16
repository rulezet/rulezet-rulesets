rule TTP_XOR_MULT_DOSStub_a2f3 {
  strings:
    $key_a2f3 = { f6 9b [2] 82 83 [2] c5 81 [2] 82 90 [2] cc 9c [2] c0 96 [2] d7 9d [2] cc d3 [2] f1 }

  condition:
    any of them
}