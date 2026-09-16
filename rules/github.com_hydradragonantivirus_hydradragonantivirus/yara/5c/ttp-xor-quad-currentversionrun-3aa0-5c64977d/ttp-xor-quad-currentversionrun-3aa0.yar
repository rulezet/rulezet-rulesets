rule TTP_XOR_QUAD_CurrentVersionRun_3aa0 {
  strings:
    $key_3aa0 = { 69 cf [2] 4d c1 [2] 66 ed [2] 48 cf [2] 5c d4 [2] 53 ce [2] 4d d3 [2] 4f d2 [2] 54 d4 [2] 48 d3 [2] 54 fc }

  condition:
    any of them
}