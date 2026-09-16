rule TTP_XOR_QUAD_CurrentVersionRun_1ba0 {
  strings:
    $key_1ba0 = { 48 cf [2] 6c c1 [2] 47 ed [2] 69 cf [2] 7d d4 [2] 72 ce [2] 6c d3 [2] 6e d2 [2] 75 d4 [2] 69 d3 [2] 75 fc }

  condition:
    any of them
}