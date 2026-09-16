rule TTP_XOR_MULT_DOSStub_aa81 {
  strings:
    $key_aa81 = { fe e9 [2] 8a f1 [2] cd f3 [2] 8a e2 [2] c4 ee [2] c8 e4 [2] df ef [2] c4 a1 [2] f9 }

  condition:
    any of them
}