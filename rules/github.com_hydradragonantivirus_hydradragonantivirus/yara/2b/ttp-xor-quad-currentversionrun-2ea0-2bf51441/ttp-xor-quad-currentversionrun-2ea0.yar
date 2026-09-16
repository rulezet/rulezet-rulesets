rule TTP_XOR_QUAD_CurrentVersionRun_2ea0 {
  strings:
    $key_2ea0 = { 7d cf [2] 59 c1 [2] 72 ed [2] 5c cf [2] 48 d4 [2] 47 ce [2] 59 d3 [2] 5b d2 [2] 40 d4 [2] 5c d3 [2] 40 fc }

  condition:
    any of them
}