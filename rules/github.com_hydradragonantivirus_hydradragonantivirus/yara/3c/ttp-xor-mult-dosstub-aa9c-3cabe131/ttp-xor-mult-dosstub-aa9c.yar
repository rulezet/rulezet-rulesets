rule TTP_XOR_MULT_DOSStub_aa9c {
  strings:
    $key_aa9c = { fe f4 [2] 8a ec [2] cd ee [2] 8a ff [2] c4 f3 [2] c8 f9 [2] df f2 [2] c4 bc [2] f9 }

  condition:
    any of them
}