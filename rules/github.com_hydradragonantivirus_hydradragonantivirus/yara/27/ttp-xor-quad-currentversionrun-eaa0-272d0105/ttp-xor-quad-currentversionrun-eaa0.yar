rule TTP_XOR_QUAD_CurrentVersionRun_eaa0 {
  strings:
    $key_eaa0 = { b9 cf [2] 9d c1 [2] b6 ed [2] 98 cf [2] 8c d4 [2] 83 ce [2] 9d d3 [2] 9f d2 [2] 84 d4 [2] 98 d3 [2] 84 fc }

  condition:
    any of them
}