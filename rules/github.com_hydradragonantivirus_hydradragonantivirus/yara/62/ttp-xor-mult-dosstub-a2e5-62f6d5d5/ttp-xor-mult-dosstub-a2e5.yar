rule TTP_XOR_MULT_DOSStub_a2e5 {
  strings:
    $key_a2e5 = { f6 8d [2] 82 95 [2] c5 97 [2] 82 86 [2] cc 8a [2] c0 80 [2] d7 8b [2] cc c5 [2] f1 }

  condition:
    any of them
}