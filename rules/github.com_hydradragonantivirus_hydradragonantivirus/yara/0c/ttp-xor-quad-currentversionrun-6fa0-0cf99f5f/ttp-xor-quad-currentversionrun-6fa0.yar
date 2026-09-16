rule TTP_XOR_QUAD_CurrentVersionRun_6fa0 {
  strings:
    $key_6fa0 = { 3c cf [2] 18 c1 [2] 33 ed [2] 1d cf [2] 09 d4 [2] 06 ce [2] 18 d3 [2] 1a d2 [2] 01 d4 [2] 1d d3 [2] 01 fc }

  condition:
    any of them
}