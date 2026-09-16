rule TTP_XOR_MULT_DOSStub_afa1 {
  strings:
    $key_afa1 = { fb c9 [2] 8f d1 [2] c8 d3 [2] 8f c2 [2] c1 ce [2] cd c4 [2] da cf [2] c1 81 [2] fc }

  condition:
    any of them
}