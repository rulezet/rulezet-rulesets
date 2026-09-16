rule TTP_XOR_MULT_DOSStub_aaa4 {
  strings:
    $key_aaa4 = { fe cc [2] 8a d4 [2] cd d6 [2] 8a c7 [2] c4 cb [2] c8 c1 [2] df ca [2] c4 84 [2] f9 }

  condition:
    any of them
}