rule TTP_XOR_MULT_DOSStub_a2e2 {
  strings:
    $key_a2e2 = { f6 8a [2] 82 92 [2] c5 90 [2] 82 81 [2] cc 8d [2] c0 87 [2] d7 8c [2] cc c2 [2] f1 }

  condition:
    any of them
}