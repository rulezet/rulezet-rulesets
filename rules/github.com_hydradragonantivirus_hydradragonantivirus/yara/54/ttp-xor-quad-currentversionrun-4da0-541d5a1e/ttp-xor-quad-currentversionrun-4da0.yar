rule TTP_XOR_QUAD_CurrentVersionRun_4da0 {
  strings:
    $key_4da0 = { 1e cf [2] 3a c1 [2] 11 ed [2] 3f cf [2] 2b d4 [2] 24 ce [2] 3a d3 [2] 38 d2 [2] 23 d4 [2] 3f d3 [2] 23 fc }

  condition:
    any of them
}