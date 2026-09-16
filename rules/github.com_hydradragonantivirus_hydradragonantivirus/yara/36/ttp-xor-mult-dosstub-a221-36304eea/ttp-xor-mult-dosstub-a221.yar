rule TTP_XOR_MULT_DOSStub_a221 {
  strings:
    $key_a221 = { f6 49 [2] 82 51 [2] c5 53 [2] 82 42 [2] cc 4e [2] c0 44 [2] d7 4f [2] cc 01 [2] f1 }

  condition:
    any of them
}