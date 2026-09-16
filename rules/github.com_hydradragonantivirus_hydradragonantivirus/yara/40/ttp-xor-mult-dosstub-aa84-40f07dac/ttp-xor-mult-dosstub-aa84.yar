rule TTP_XOR_MULT_DOSStub_aa84 {
  strings:
    $key_aa84 = { fe ec [2] 8a f4 [2] cd f6 [2] 8a e7 [2] c4 eb [2] c8 e1 [2] df ea [2] c4 a4 [2] f9 }

  condition:
    any of them
}