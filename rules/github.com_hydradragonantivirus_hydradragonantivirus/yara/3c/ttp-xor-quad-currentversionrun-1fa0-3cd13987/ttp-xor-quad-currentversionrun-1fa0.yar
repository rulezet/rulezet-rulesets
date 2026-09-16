rule TTP_XOR_QUAD_CurrentVersionRun_1fa0 {
  strings:
    $key_1fa0 = { 4c cf [2] 68 c1 [2] 43 ed [2] 6d cf [2] 79 d4 [2] 76 ce [2] 68 d3 [2] 6a d2 [2] 71 d4 [2] 6d d3 [2] 71 fc }

  condition:
    any of them
}