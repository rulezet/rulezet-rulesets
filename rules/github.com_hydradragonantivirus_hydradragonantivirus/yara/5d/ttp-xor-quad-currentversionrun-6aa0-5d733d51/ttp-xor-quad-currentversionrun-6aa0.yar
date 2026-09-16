rule TTP_XOR_QUAD_CurrentVersionRun_6aa0 {
  strings:
    $key_6aa0 = { 39 cf [2] 1d c1 [2] 36 ed [2] 18 cf [2] 0c d4 [2] 03 ce [2] 1d d3 [2] 1f d2 [2] 04 d4 [2] 18 d3 [2] 04 fc }

  condition:
    any of them
}