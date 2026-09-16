rule TTP_XOR_MULT_DOSStub_a2a0 {
  strings:
    $key_a2a0 = { f6 c8 [2] 82 d0 [2] c5 d2 [2] 82 c3 [2] cc cf [2] c0 c5 [2] d7 ce [2] cc 80 [2] f1 }

  condition:
    any of them
}