rule TTP_XOR_MULT_DOSStub_a2f4 {
  strings:
    $key_a2f4 = { f6 9c [2] 82 84 [2] c5 86 [2] 82 97 [2] cc 9b [2] c0 91 [2] d7 9a [2] cc d4 [2] f1 }

  condition:
    any of them
}