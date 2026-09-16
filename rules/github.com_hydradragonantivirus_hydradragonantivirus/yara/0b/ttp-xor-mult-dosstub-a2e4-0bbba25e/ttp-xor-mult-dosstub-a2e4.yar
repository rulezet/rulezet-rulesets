rule TTP_XOR_MULT_DOSStub_a2e4 {
  strings:
    $key_a2e4 = { f6 8c [2] 82 94 [2] c5 96 [2] 82 87 [2] cc 8b [2] c0 81 [2] d7 8a [2] cc c4 [2] f1 }

  condition:
    any of them
}