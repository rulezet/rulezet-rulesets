rule TTP_XOR_MULT_DOSStub_a205 {
  strings:
    $key_a205 = { f6 6d [2] 82 75 [2] c5 77 [2] 82 66 [2] cc 6a [2] c0 60 [2] d7 6b [2] cc 25 [2] f1 }

  condition:
    any of them
}