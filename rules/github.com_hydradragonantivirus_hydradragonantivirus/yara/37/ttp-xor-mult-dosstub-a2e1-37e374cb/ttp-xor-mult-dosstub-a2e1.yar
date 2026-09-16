rule TTP_XOR_MULT_DOSStub_a2e1 {
  strings:
    $key_a2e1 = { f6 89 [2] 82 91 [2] c5 93 [2] 82 82 [2] cc 8e [2] c0 84 [2] d7 8f [2] cc c1 [2] f1 }

  condition:
    any of them
}