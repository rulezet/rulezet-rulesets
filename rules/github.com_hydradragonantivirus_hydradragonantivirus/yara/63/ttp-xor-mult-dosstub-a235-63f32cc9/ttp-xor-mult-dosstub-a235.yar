rule TTP_XOR_MULT_DOSStub_a235 {
  strings:
    $key_a235 = { f6 5d [2] 82 45 [2] c5 47 [2] 82 56 [2] cc 5a [2] c0 50 [2] d7 5b [2] cc 15 [2] f1 }

  condition:
    any of them
}