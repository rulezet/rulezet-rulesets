rule TTP_XOR_MULT_DOSStub_aa8b {
  strings:
    $key_aa8b = { fe e3 [2] 8a fb [2] cd f9 [2] 8a e8 [2] c4 e4 [2] c8 ee [2] df e5 [2] c4 ab [2] f9 }

  condition:
    any of them
}