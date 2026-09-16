rule TTP_XOR_MULT_DOSStub_a2f9 {
  strings:
    $key_a2f9 = { f6 91 [2] 82 89 [2] c5 8b [2] 82 9a [2] cc 96 [2] c0 9c [2] d7 97 [2] cc d9 [2] f1 }

  condition:
    any of them
}