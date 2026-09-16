rule TTP_XOR_QUAD_CurrentVersionRun_eda1 {
  strings:
    $key_eda1 = { be ce [2] 9a c0 [2] b1 ec [2] 9f ce [2] 8b d5 [2] 84 cf [2] 9a d2 [2] 98 d3 [2] 83 d5 [2] 9f d2 [2] 83 fd }

  condition:
    any of them
}