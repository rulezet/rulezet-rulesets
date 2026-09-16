rule TTP_XOR_MULT_DOSStub_a269 {
  strings:
    $key_a269 = { f6 01 [2] 82 19 [2] c5 1b [2] 82 0a [2] cc 06 [2] c0 0c [2] d7 07 [2] cc 49 [2] f1 }

  condition:
    any of them
}