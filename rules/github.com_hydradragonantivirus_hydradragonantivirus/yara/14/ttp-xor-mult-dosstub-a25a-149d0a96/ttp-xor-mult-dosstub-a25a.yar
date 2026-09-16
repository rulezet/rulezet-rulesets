rule TTP_XOR_MULT_DOSStub_a25a {
  strings:
    $key_a25a = { f6 32 [2] 82 2a [2] c5 28 [2] 82 39 [2] cc 35 [2] c0 3f [2] d7 34 [2] cc 7a [2] f1 }

  condition:
    any of them
}