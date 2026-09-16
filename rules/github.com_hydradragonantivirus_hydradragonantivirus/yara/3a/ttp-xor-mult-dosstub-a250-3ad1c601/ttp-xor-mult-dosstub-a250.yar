rule TTP_XOR_MULT_DOSStub_a250 {
  strings:
    $key_a250 = { f6 38 [2] 82 20 [2] c5 22 [2] 82 33 [2] cc 3f [2] c0 35 [2] d7 3e [2] cc 70 [2] f1 }

  condition:
    any of them
}