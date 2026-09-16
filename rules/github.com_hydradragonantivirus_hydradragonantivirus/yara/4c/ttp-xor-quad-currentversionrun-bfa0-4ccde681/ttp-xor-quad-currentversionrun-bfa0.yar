rule TTP_XOR_QUAD_CurrentVersionRun_bfa0 {
  strings:
    $key_bfa0 = { ec cf [2] c8 c1 [2] e3 ed [2] cd cf [2] d9 d4 [2] d6 ce [2] c8 d3 [2] ca d2 [2] d1 d4 [2] cd d3 [2] d1 fc }

  condition:
    any of them
}