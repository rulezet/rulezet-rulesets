rule TTP_XOR_MULT_DOSStub_a2b7 {
  strings:
    $key_a2b7 = { f6 df [2] 82 c7 [2] c5 c5 [2] 82 d4 [2] cc d8 [2] c0 d2 [2] d7 d9 [2] cc 97 [2] f1 }

  condition:
    any of them
}