rule TTP_XOR_MULT_DOSStub_a2a9 {
  strings:
    $key_a2a9 = { f6 c1 [2] 82 d9 [2] c5 db [2] 82 ca [2] cc c6 [2] c0 cc [2] d7 c7 [2] cc 89 [2] f1 }

  condition:
    any of them
}