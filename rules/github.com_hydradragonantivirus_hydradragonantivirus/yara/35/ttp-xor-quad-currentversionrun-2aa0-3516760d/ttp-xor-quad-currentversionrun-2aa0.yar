rule TTP_XOR_QUAD_CurrentVersionRun_2aa0 {
  strings:
    $key_2aa0 = { 79 cf [2] 5d c1 [2] 76 ed [2] 58 cf [2] 4c d4 [2] 43 ce [2] 5d d3 [2] 5f d2 [2] 44 d4 [2] 58 d3 [2] 44 fc }

  condition:
    any of them
}