rule TTP_XOR_MULT_DOSStub_a268 {
  strings:
    $key_a268 = { f6 00 [2] 82 18 [2] c5 1a [2] 82 0b [2] cc 07 [2] c0 0d [2] d7 06 [2] cc 48 [2] f1 }

  condition:
    any of them
}