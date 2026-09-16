rule TTP_XOR_QUAD_CurrentVersionRun_4aa0 {
  strings:
    $key_4aa0 = { 19 cf [2] 3d c1 [2] 16 ed [2] 38 cf [2] 2c d4 [2] 23 ce [2] 3d d3 [2] 3f d2 [2] 24 d4 [2] 38 d3 [2] 24 fc }

  condition:
    any of them
}