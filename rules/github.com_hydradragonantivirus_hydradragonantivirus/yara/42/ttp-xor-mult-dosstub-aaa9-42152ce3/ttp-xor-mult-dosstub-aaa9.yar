rule TTP_XOR_MULT_DOSStub_aaa9 {
  strings:
    $key_aaa9 = { fe c1 [2] 8a d9 [2] cd db [2] 8a ca [2] c4 c6 [2] c8 cc [2] df c7 [2] c4 89 [2] f9 }

  condition:
    any of them
}