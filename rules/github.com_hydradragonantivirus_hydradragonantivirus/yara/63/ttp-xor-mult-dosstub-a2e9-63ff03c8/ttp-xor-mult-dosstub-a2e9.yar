rule TTP_XOR_MULT_DOSStub_a2e9 {
  strings:
    $key_a2e9 = { f6 81 [2] 82 99 [2] c5 9b [2] 82 8a [2] cc 86 [2] c0 8c [2] d7 87 [2] cc c9 [2] f1 }

  condition:
    any of them
}