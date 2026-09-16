rule TTP_XOR_MULT_DOSStub_afa6 {
  strings:
    $key_afa6 = { fb ce [2] 8f d6 [2] c8 d4 [2] 8f c5 [2] c1 c9 [2] cd c3 [2] da c8 [2] c1 86 [2] fc }

  condition:
    any of them
}