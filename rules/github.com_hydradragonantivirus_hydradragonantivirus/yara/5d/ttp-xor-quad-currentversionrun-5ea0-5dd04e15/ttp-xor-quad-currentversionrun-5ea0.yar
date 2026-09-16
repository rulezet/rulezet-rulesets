rule TTP_XOR_QUAD_CurrentVersionRun_5ea0 {
  strings:
    $key_5ea0 = { 0d cf [2] 29 c1 [2] 02 ed [2] 2c cf [2] 38 d4 [2] 37 ce [2] 29 d3 [2] 2b d2 [2] 30 d4 [2] 2c d3 [2] 30 fc }

  condition:
    any of them
}