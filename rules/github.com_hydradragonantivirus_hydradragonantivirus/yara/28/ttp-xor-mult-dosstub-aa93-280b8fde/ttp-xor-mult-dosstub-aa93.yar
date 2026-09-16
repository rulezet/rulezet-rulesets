rule TTP_XOR_MULT_DOSStub_aa93 {
  strings:
    $key_aa93 = { fe fb [2] 8a e3 [2] cd e1 [2] 8a f0 [2] c4 fc [2] c8 f6 [2] df fd [2] c4 b3 [2] f9 }

  condition:
    any of them
}