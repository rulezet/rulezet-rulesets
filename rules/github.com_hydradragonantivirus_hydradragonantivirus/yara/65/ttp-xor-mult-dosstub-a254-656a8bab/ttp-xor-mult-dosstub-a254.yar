rule TTP_XOR_MULT_DOSStub_a254 {
  strings:
    $key_a254 = { f6 3c [2] 82 24 [2] c5 26 [2] 82 37 [2] cc 3b [2] c0 31 [2] d7 3a [2] cc 74 [2] f1 }

  condition:
    any of them
}