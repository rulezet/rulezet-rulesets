rule TTP_XOR_MULT_DOSStub_a215 {
  strings:
    $key_a215 = { f6 7d [2] 82 65 [2] c5 67 [2] 82 76 [2] cc 7a [2] c0 70 [2] d7 7b [2] cc 35 [2] f1 }

  condition:
    any of them
}