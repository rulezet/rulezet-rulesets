rule TTP_XOR_QUAD_CurrentVersionRun_91a0 {
  strings:
    $key_91a0 = { c2 cf [2] e6 c1 [2] cd ed [2] e3 cf [2] f7 d4 [2] f8 ce [2] e6 d3 [2] e4 d2 [2] ff d4 [2] e3 d3 [2] ff fc }

  condition:
    any of them
}