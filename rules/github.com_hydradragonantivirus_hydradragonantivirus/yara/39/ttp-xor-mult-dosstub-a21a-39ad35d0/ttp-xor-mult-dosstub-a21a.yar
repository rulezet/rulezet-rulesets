rule TTP_XOR_MULT_DOSStub_a21a {
  strings:
    $key_a21a = { f6 72 [2] 82 6a [2] c5 68 [2] 82 79 [2] cc 75 [2] c0 7f [2] d7 74 [2] cc 3a [2] f1 }

  condition:
    any of them
}