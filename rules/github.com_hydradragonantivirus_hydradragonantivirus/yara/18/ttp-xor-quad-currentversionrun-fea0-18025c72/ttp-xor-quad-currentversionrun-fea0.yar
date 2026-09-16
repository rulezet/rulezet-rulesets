rule TTP_XOR_QUAD_CurrentVersionRun_fea0 {
  strings:
    $key_fea0 = { ad cf [2] 89 c1 [2] a2 ed [2] 8c cf [2] 98 d4 [2] 97 ce [2] 89 d3 [2] 8b d2 [2] 90 d4 [2] 8c d3 [2] 90 fc }

  condition:
    any of them
}