rule TTP_XOR_MULT_DOSStub_a214 {
  strings:
    $key_a214 = { f6 7c [2] 82 64 [2] c5 66 [2] 82 77 [2] cc 7b [2] c0 71 [2] d7 7a [2] cc 34 [2] f1 }

  condition:
    any of them
}