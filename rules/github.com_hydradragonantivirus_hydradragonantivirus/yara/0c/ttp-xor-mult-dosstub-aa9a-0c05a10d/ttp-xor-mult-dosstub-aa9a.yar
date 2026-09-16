rule TTP_XOR_MULT_DOSStub_aa9a {
  strings:
    $key_aa9a = { fe f2 [2] 8a ea [2] cd e8 [2] 8a f9 [2] c4 f5 [2] c8 ff [2] df f4 [2] c4 ba [2] f9 }

  condition:
    any of them
}