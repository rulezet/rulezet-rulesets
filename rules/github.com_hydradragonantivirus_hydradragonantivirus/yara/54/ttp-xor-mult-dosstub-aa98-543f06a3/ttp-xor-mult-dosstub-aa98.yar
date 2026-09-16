rule TTP_XOR_MULT_DOSStub_aa98 {
  strings:
    $key_aa98 = { fe f0 [2] 8a e8 [2] cd ea [2] 8a fb [2] c4 f7 [2] c8 fd [2] df f6 [2] c4 b8 [2] f9 }

  condition:
    any of them
}