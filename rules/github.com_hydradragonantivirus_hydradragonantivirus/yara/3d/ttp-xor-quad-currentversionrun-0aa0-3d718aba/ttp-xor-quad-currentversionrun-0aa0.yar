rule TTP_XOR_QUAD_CurrentVersionRun_0aa0 {
  strings:
    $key_0aa0 = { 59 cf [2] 7d c1 [2] 56 ed [2] 78 cf [2] 6c d4 [2] 63 ce [2] 7d d3 [2] 7f d2 [2] 64 d4 [2] 78 d3 [2] 64 fc }

  condition:
    any of them
}