rule TTP_XOR_MULT_DOSStub_aba0 {
  strings:
    $key_aba0 = { ff c8 [2] 8b d0 [2] cc d2 [2] 8b c3 [2] c5 cf [2] c9 c5 [2] de ce [2] c5 80 [2] f8 }

  condition:
    any of them
}