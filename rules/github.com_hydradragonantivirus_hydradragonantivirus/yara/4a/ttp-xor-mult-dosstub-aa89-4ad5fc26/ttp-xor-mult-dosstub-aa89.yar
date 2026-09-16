rule TTP_XOR_MULT_DOSStub_aa89 {
  strings:
    $key_aa89 = { fe e1 [2] 8a f9 [2] cd fb [2] 8a ea [2] c4 e6 [2] c8 ec [2] df e7 [2] c4 a9 [2] f9 }

  condition:
    any of them
}