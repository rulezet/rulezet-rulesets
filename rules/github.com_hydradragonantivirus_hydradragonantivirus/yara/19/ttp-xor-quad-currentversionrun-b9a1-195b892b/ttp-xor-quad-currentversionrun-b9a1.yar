rule TTP_XOR_QUAD_CurrentVersionRun_b9a1 {
  strings:
    $key_b9a1 = { ea ce [2] ce c0 [2] e5 ec [2] cb ce [2] df d5 [2] d0 cf [2] ce d2 [2] cc d3 [2] d7 d5 [2] cb d2 [2] d7 fd }

  condition:
    any of them
}