rule TTP_XOR_MULT_DOSStub_a22c {
  strings:
    $key_a22c = { f6 44 [2] 82 5c [2] c5 5e [2] 82 4f [2] cc 43 [2] c0 49 [2] d7 42 [2] cc 0c [2] f1 }

  condition:
    any of them
}