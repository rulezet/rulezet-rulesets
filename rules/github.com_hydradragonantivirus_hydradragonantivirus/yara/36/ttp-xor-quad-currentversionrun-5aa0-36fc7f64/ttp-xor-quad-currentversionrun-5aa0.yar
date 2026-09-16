rule TTP_XOR_QUAD_CurrentVersionRun_5aa0 {
  strings:
    $key_5aa0 = { 09 cf [2] 2d c1 [2] 06 ed [2] 28 cf [2] 3c d4 [2] 33 ce [2] 2d d3 [2] 2f d2 [2] 34 d4 [2] 28 d3 [2] 34 fc }

  condition:
    any of them
}