rule TTP_XOR_MULT_DOSStub_a2b4 {
  strings:
    $key_a2b4 = { f6 dc [2] 82 c4 [2] c5 c6 [2] 82 d7 [2] cc db [2] c0 d1 [2] d7 da [2] cc 94 [2] f1 }

  condition:
    any of them
}