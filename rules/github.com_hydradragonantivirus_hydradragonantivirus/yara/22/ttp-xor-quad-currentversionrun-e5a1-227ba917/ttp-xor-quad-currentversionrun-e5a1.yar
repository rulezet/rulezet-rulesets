rule TTP_XOR_QUAD_CurrentVersionRun_e5a1 {
  strings:
    $key_e5a1 = { b6 ce [2] 92 c0 [2] b9 ec [2] 97 ce [2] 83 d5 [2] 8c cf [2] 92 d2 [2] 90 d3 [2] 8b d5 [2] 97 d2 [2] 8b fd }

  condition:
    any of them
}