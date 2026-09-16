rule TTP_XOR_QUAD_CurrentVersionRun_4fa0 {
  strings:
    $key_4fa0 = { 1c cf [2] 38 c1 [2] 13 ed [2] 3d cf [2] 29 d4 [2] 26 ce [2] 38 d3 [2] 3a d2 [2] 21 d4 [2] 3d d3 [2] 21 fc }

  condition:
    any of them
}