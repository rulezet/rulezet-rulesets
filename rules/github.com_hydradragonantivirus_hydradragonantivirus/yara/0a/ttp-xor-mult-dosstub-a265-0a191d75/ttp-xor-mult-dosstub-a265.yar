rule TTP_XOR_MULT_DOSStub_a265 {
  strings:
    $key_a265 = { f6 0d [2] 82 15 [2] c5 17 [2] 82 06 [2] cc 0a [2] c0 00 [2] d7 0b [2] cc 45 [2] f1 }

  condition:
    any of them
}