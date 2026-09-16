rule TTP_XOR_QUAD_CurrentVersionRun_7aa0 {
  strings:
    $key_7aa0 = { 29 cf [2] 0d c1 [2] 26 ed [2] 08 cf [2] 1c d4 [2] 13 ce [2] 0d d3 [2] 0f d2 [2] 14 d4 [2] 08 d3 [2] 14 fc }

  condition:
    any of them
}