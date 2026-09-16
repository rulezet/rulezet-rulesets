rule TTP_XOR_QUAD_CurrentVersionRun_ada0 {
  strings:
    $key_ada0 = { fe cf [2] da c1 [2] f1 ed [2] df cf [2] cb d4 [2] c4 ce [2] da d3 [2] d8 d2 [2] c3 d4 [2] df d3 [2] c3 fc }

  condition:
    any of them
}