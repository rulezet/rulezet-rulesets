rule TTP_XOR_MULT_DOSStub_a244 {
  strings:
    $key_a244 = { f6 2c [2] 82 34 [2] c5 36 [2] 82 27 [2] cc 2b [2] c0 21 [2] d7 2a [2] cc 64 [2] f1 }

  condition:
    any of them
}