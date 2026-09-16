rule TTP_XOR_MULT_DOSStub_aa9d {
  strings:
    $key_aa9d = { fe f5 [2] 8a ed [2] cd ef [2] 8a fe [2] c4 f2 [2] c8 f8 [2] df f3 [2] c4 bd [2] f9 }

  condition:
    any of them
}