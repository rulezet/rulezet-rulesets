rule TTP_XOR_MULT_DOSStub_a238 {
  strings:
    $key_a238 = { f6 50 [2] 82 48 [2] c5 4a [2] 82 5b [2] cc 57 [2] c0 5d [2] d7 56 [2] cc 18 [2] f1 }

  condition:
    any of them
}