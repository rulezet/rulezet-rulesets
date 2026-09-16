rule TTP_XOR_MULT_DOSStub_a278 {
  strings:
    $key_a278 = { f6 10 [2] 82 08 [2] c5 0a [2] 82 1b [2] cc 17 [2] c0 1d [2] d7 16 [2] cc 58 [2] f1 }

  condition:
    any of them
}