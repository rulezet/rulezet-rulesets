rule TTP_XOR_QUAD_CurrentVersionRun_3ea0 {
  strings:
    $key_3ea0 = { 6d cf [2] 49 c1 [2] 62 ed [2] 4c cf [2] 58 d4 [2] 57 ce [2] 49 d3 [2] 4b d2 [2] 50 d4 [2] 4c d3 [2] 50 fc }

  condition:
    any of them
}