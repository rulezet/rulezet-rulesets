rule TTP_XOR_MULT_DOSStub_a241 {
  strings:
    $key_a241 = { f6 29 [2] 82 31 [2] c5 33 [2] 82 22 [2] cc 2e [2] c0 24 [2] d7 2f [2] cc 61 [2] f1 }

  condition:
    any of them
}