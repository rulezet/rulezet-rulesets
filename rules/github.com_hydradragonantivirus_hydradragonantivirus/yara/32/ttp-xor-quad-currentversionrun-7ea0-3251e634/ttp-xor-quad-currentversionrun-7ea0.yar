rule TTP_XOR_QUAD_CurrentVersionRun_7ea0 {
  strings:
    $key_7ea0 = { 2d cf [2] 09 c1 [2] 22 ed [2] 0c cf [2] 18 d4 [2] 17 ce [2] 09 d3 [2] 0b d2 [2] 10 d4 [2] 0c d3 [2] 10 fc }

  condition:
    any of them
}