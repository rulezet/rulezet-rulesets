rule TTP_XOR_MULT_DOSStub_a263 {
  strings:
    $key_a263 = { f6 0b [2] 82 13 [2] c5 11 [2] 82 00 [2] cc 0c [2] c0 06 [2] d7 0d [2] cc 43 [2] f1 }

  condition:
    any of them
}