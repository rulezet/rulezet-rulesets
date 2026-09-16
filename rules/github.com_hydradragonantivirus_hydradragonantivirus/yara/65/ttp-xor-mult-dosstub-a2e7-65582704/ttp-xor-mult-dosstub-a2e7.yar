rule TTP_XOR_MULT_DOSStub_a2e7 {
  strings:
    $key_a2e7 = { f6 8f [2] 82 97 [2] c5 95 [2] 82 84 [2] cc 88 [2] c0 82 [2] d7 89 [2] cc c7 [2] f1 }

  condition:
    any of them
}