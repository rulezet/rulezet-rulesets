rule TTP_XOR_MULT_DOSStub_a2b2 {
  strings:
    $key_a2b2 = { f6 da [2] 82 c2 [2] c5 c0 [2] 82 d1 [2] cc dd [2] c0 d7 [2] d7 dc [2] cc 92 [2] f1 }

  condition:
    any of them
}