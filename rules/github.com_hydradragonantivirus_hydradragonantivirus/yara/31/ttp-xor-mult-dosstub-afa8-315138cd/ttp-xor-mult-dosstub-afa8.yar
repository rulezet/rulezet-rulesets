rule TTP_XOR_MULT_DOSStub_afa8 {
  strings:
    $key_afa8 = { fb c0 [2] 8f d8 [2] c8 da [2] 8f cb [2] c1 c7 [2] cd cd [2] da c6 [2] c1 88 [2] fc }

  condition:
    any of them
}