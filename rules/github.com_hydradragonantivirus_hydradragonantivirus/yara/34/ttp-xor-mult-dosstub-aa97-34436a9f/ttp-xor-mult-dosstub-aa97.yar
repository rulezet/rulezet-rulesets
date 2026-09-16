rule TTP_XOR_MULT_DOSStub_aa97 {
  strings:
    $key_aa97 = { fe ff [2] 8a e7 [2] cd e5 [2] 8a f4 [2] c4 f8 [2] c8 f2 [2] df f9 [2] c4 b7 [2] f9 }

  condition:
    any of them
}