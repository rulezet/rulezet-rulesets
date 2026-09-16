rule TTP_XOR_MULT_DOSStub_aa83 {
  strings:
    $key_aa83 = { fe eb [2] 8a f3 [2] cd f1 [2] 8a e0 [2] c4 ec [2] c8 e6 [2] df ed [2] c4 a3 [2] f9 }

  condition:
    any of them
}