rule TTP_XOR_MULT_DOSStub_afa0 {
  strings:
    $key_afa0 = { fb c8 [2] 8f d0 [2] c8 d2 [2] 8f c3 [2] c1 cf [2] cd c5 [2] da ce [2] c1 80 [2] fc }

  condition:
    any of them
}