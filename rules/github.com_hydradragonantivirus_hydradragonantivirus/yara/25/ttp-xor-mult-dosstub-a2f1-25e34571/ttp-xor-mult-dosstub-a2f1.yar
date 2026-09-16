rule TTP_XOR_MULT_DOSStub_a2f1 {
  strings:
    $key_a2f1 = { f6 99 [2] 82 81 [2] c5 83 [2] 82 92 [2] cc 9e [2] c0 94 [2] d7 9f [2] cc d1 [2] f1 }

  condition:
    any of them
}