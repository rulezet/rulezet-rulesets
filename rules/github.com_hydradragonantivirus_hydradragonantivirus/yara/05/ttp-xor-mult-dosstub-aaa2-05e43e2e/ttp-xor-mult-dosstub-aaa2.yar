rule TTP_XOR_MULT_DOSStub_aaa2 {
  strings:
    $key_aaa2 = { fe ca [2] 8a d2 [2] cd d0 [2] 8a c1 [2] c4 cd [2] c8 c7 [2] df cc [2] c4 82 [2] f9 }

  condition:
    any of them
}