rule TTP_XOR_MULT_DOSStub_a2f6 {
  strings:
    $key_a2f6 = { f6 9e [2] 82 86 [2] c5 84 [2] 82 95 [2] cc 99 [2] c0 93 [2] d7 98 [2] cc d6 [2] f1 }

  condition:
    any of them
}