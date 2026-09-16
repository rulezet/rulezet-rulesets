rule TTP_XOR_MULT_DOSStub_a232 {
  strings:
    $key_a232 = { f6 5a [2] 82 42 [2] c5 40 [2] 82 51 [2] cc 5d [2] c0 57 [2] d7 5c [2] cc 12 [2] f1 }

  condition:
    any of them
}